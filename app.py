from __future__ import annotations

import hashlib
import hmac
import html
import ipaddress
import mimetypes
import os
import platform
import secrets
import socket
import sqlite3
import subprocess
import threading
from contextlib import closing
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DB_PATH = Path(os.environ.get("IP_REGISTRY_DB", "ips.db"))
PING_INTERVAL_SECONDS = 30 * 60
PING_LOG_RETENTION_DAYS = 7
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "5000"))

HOST_TYPE_OPTIONS = ["NOTEBOOK", "DESKTOP", "SERVER", "IMPRESORA", "ROUTER", "OTRO"]
AUTH_COOKIE_NAME = "ip_registry_session"
SESSION_SECRET = os.environ.get("SESSION_SECRET", "dev-change-me")
DEMO_ADMIN_ENABLED = os.environ.get("DEMO_ADMIN_ENABLED", "1") == "1"
ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
VALID_ROLES = {ROLE_ADMIN, ROLE_OPERATOR}

_db_lock = threading.Lock()


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _db_lock, closing(get_connection()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ip_registry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                alias TEXT,
                host_name TEXT,
                host_type TEXT,
                location TEXT,
                notes TEXT,
                hostname TEXT,
                last_ping_at TEXT,
                last_status TEXT,
                last_output TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'operator',
                first_name TEXT,
                last_name TEXT,
                photo_url TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ping_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                hostname TEXT,
                status TEXT NOT NULL,
                output TEXT,
                pinged_at TEXT NOT NULL
            )
            """
        )
        _ensure_ip_columns(conn)
        _ensure_user_columns(conn)
        _ensure_demo_admin(conn)
        conn.commit()


def _ensure_ip_columns(conn: sqlite3.Connection) -> None:
    current = {row["name"] for row in conn.execute("PRAGMA table_info(ip_registry)").fetchall()}
    missing = {
        "host_name": "ALTER TABLE ip_registry ADD COLUMN host_name TEXT",
        "host_type": "ALTER TABLE ip_registry ADD COLUMN host_type TEXT",
        "location": "ALTER TABLE ip_registry ADD COLUMN location TEXT",
        "notes": "ALTER TABLE ip_registry ADD COLUMN notes TEXT",
    }
    for column, statement in missing.items():
        if column not in current:
            conn.execute(statement)


def _ensure_user_columns(conn: sqlite3.Connection) -> None:
    current = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    missing = {
        "role": "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'operator'",
        "first_name": "ALTER TABLE users ADD COLUMN first_name TEXT",
        "last_name": "ALTER TABLE users ADD COLUMN last_name TEXT",
        "photo_url": "ALTER TABLE users ADD COLUMN photo_url TEXT",
    }
    for column, statement in missing.items():
        if column not in current:
            conn.execute(statement)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_password(password: str, salt: str | None = None) -> str:
    raw_salt = bytes.fromhex(salt) if salt else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), raw_salt, 200_000)
    return f"{raw_salt.hex()}:{digest.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    salt, expected = stored_hash.split(":", maxsplit=1)
    computed = _hash_password(password, salt=salt).split(":", maxsplit=1)[1]
    return hmac.compare_digest(expected, computed)


def _sanitize_role(role: str) -> str:
    value = role.strip().lower()
    if value not in VALID_ROLES:
        return ROLE_OPERATOR
    return value


def _sanitize_photo_url(photo_url: str) -> str | None:
    value = photo_url.strip()
    return value or None


def _ensure_demo_admin(conn: sqlite3.Connection) -> None:
    if not DEMO_ADMIN_ENABLED:
        return
    existing = conn.execute("SELECT 1 FROM users WHERE username = ?", ("admin",)).fetchone()
    if existing is None:
        conn.execute(
            """
            INSERT INTO users (username, password_hash, role, first_name, last_name, photo_url, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            ("admin", _hash_password("admin"), ROLE_ADMIN, "Admin", "Demo", None, _now_iso()),
        )


def get_user_by_username(username: str) -> dict[str, str | None] | None:
    with _db_lock, closing(get_connection()) as conn:
        row = conn.execute(
            "SELECT username, role, first_name, last_name, photo_url, created_at FROM users WHERE username = ?",
            (username.strip(),),
        ).fetchone()
    return dict(row) if row else None


def authenticate_user(username: str, password: str) -> bool:
    with _db_lock, closing(get_connection()) as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (username.strip(),)).fetchone()
    if row is None:
        return False
    return _verify_password(password, row["password_hash"])


def create_user_by_admin(
    username: str,
    password: str,
    role: str,
    first_name: str = "",
    last_name: str = "",
    photo_url: str = "",
) -> tuple[bool, str]:
    clean_username = username.strip()
    if len(clean_username) < 3:
        return False, "El usuario debe tener al menos 3 caracteres"
    if len(password) < 4:
        return False, "La contraseña debe tener al menos 4 caracteres"

    clean_role = _sanitize_role(role)
    with _db_lock, closing(get_connection()) as conn:
        try:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, role, first_name, last_name, photo_url, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    clean_username,
                    _hash_password(password),
                    clean_role,
                    first_name.strip() or None,
                    last_name.strip() or None,
                    _sanitize_photo_url(photo_url),
                    _now_iso(),
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return False, "El usuario ya existe"
    return True, "Usuario creado"


def update_profile(
    current_username: str,
    new_username: str,
    first_name: str,
    last_name: str,
    photo_url: str,
) -> tuple[bool, str, str]:
    clean_new = new_username.strip()
    if len(clean_new) < 3:
        return False, "El userID debe tener al menos 3 caracteres", current_username

    with _db_lock, closing(get_connection()) as conn:
        try:
            conn.execute(
                """
                UPDATE users
                SET username = ?, first_name = ?, last_name = ?, photo_url = ?
                WHERE username = ?
                """,
                (
                    clean_new,
                    first_name.strip() or None,
                    last_name.strip() or None,
                    _sanitize_photo_url(photo_url),
                    current_username,
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return False, "Ese userID ya está en uso", current_username
    return True, "Perfil actualizado", clean_new


def admin_update_user(
    original_username: str,
    new_username: str,
    role: str,
    first_name: str,
    last_name: str,
    photo_url: str,
    new_password: str,
) -> tuple[bool, str]:
    clean_new = new_username.strip()
    if len(clean_new) < 3:
        return False, "El userID debe tener al menos 3 caracteres"

    clean_role = _sanitize_role(role)
    with _db_lock, closing(get_connection()) as conn:
        current = conn.execute("SELECT username, role FROM users WHERE username = ?", (original_username,)).fetchone()
        if current is None:
            return False, "Usuario no encontrado"

        if current["role"] == ROLE_ADMIN and clean_role != ROLE_ADMIN:
            admins = conn.execute("SELECT COUNT(*) AS qty FROM users WHERE role = ?", (ROLE_ADMIN,)).fetchone()["qty"]
            if admins <= 1:
                return False, "Debe existir al menos un admin"

        try:
            if new_password.strip():
                conn.execute(
                    """
                    UPDATE users
                    SET username = ?, role = ?, first_name = ?, last_name = ?, photo_url = ?, password_hash = ?
                    WHERE username = ?
                    """,
                    (
                        clean_new,
                        clean_role,
                        first_name.strip() or None,
                        last_name.strip() or None,
                        _sanitize_photo_url(photo_url),
                        _hash_password(new_password.strip()),
                        original_username,
                    ),
                )
            else:
                conn.execute(
                    """
                    UPDATE users
                    SET username = ?, role = ?, first_name = ?, last_name = ?, photo_url = ?
                    WHERE username = ?
                    """,
                    (
                        clean_new,
                        clean_role,
                        first_name.strip() or None,
                        last_name.strip() or None,
                        _sanitize_photo_url(photo_url),
                        original_username,
                    ),
                )
            conn.commit()
        except sqlite3.IntegrityError:
            return False, "Ese userID ya está en uso"

    return True, "Usuario actualizado"


def admin_delete_user(target_username: str, acting_username: str) -> tuple[bool, str]:
    if target_username == acting_username:
        return False, "No puedes eliminar tu propio usuario"

    with _db_lock, closing(get_connection()) as conn:
        row = conn.execute("SELECT role FROM users WHERE username = ?", (target_username,)).fetchone()
        if row is None:
            return False, "Usuario no encontrado"

        if row["role"] == ROLE_ADMIN:
            admins = conn.execute("SELECT COUNT(*) AS qty FROM users WHERE role = ?", (ROLE_ADMIN,)).fetchone()["qty"]
            if admins <= 1:
                return False, "No puedes eliminar el último admin"

        conn.execute("DELETE FROM users WHERE username = ?", (target_username,))
        conn.commit()
    return True, "Usuario eliminado"


def get_all_users() -> list[dict[str, str | None]]:
    with _db_lock, closing(get_connection()) as conn:
        rows = conn.execute(
            "SELECT username, role, first_name, last_name, photo_url, created_at FROM users ORDER BY role DESC, username ASC"
        ).fetchall()
    return [dict(r) for r in rows]


def _build_session_cookie(username: str) -> str:
    signature = hmac.new(SESSION_SECRET.encode("utf-8"), username.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{username}:{signature}"


def _read_session_username(headers) -> str | None:
    raw_cookie = headers.get("Cookie", "")
    if not raw_cookie:
        return None
    parsed = SimpleCookie()
    parsed.load(raw_cookie)
    morsel = parsed.get(AUTH_COOKIE_NAME)
    if not morsel:
        return None
    token = morsel.value
    if ":" not in token:
        return None
    username, signature = token.split(":", maxsplit=1)
    expected = hmac.new(SESSION_SECRET.encode("utf-8"), username.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    return username


def is_valid_ip(ip_value: str) -> bool:
    try:
        ipaddress.ip_address(ip_value.strip())
    except ValueError:
        return False
    return True


def register_ip(ip_address: str, alias: str | None = None) -> tuple[bool, str]:
    clean_ip = ip_address.strip()
    if not is_valid_ip(clean_ip):
        return False, "La IP no es válida"

    with _db_lock, closing(get_connection()) as conn:
        try:
            conn.execute(
                "INSERT INTO ip_registry (ip_address, alias, created_at) VALUES (?, ?, ?)",
                (clean_ip, alias.strip() if alias else None, _now_iso()),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return False, "La IP ya estaba registrada"
    return True, "IP registrada correctamente"


def update_host_details(
    ip_address: str,
    host_name: str,
    host_type: str,
    location: str,
    notes: str,
    alias: str,
) -> tuple[bool, str]:
    if host_type and host_type not in HOST_TYPE_OPTIONS:
        return False, "Tipo de host inválido"

    with _db_lock, closing(get_connection()) as conn:
        row = conn.execute("SELECT id FROM ip_registry WHERE ip_address = ?", (ip_address,)).fetchone()
        if row is None:
            return False, "No existe la IP indicada"

        conn.execute(
            """
            UPDATE ip_registry
            SET alias = ?, host_name = ?, host_type = ?, location = ?, notes = ?
            WHERE ip_address = ?
            """,
            (
                alias.strip() or None,
                host_name.strip() or None,
                host_type.strip() or None,
                location.strip() or None,
                notes.strip() or None,
                ip_address,
            ),
        )
        conn.commit()
    return True, "Host actualizado"


def resolve_hostname(ip_address: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def run_ping(ip_address: str) -> tuple[str, str]:
    system = platform.system().lower()
    cmd = ["ping", "-n", "1", "-a", ip_address] if system == "windows" else ["ping", "-c", "1", ip_address]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode == 0:
        return "OK", output.strip()
    return "ERROR", output.strip() or f"Ping fallido con código {proc.returncode}"




def _record_ping_log(conn: sqlite3.Connection, ip_address: str, hostname: str | None, status: str, output: str, pinged_at: str) -> None:
    conn.execute(
        """
        INSERT INTO ping_logs (ip_address, hostname, status, output, pinged_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (ip_address, hostname, status, output, pinged_at),
    )


def _prune_old_ping_logs(conn: sqlite3.Connection) -> None:
    threshold = (datetime.now(timezone.utc) - timedelta(days=PING_LOG_RETENTION_DAYS)).isoformat()
    conn.execute("DELETE FROM ping_logs WHERE pinged_at < ?", (threshold,))


def get_ping_logs_for_ip(ip_address: str, limit: int = 200) -> list[dict[str, str | None]]:
    with _db_lock, closing(get_connection()) as conn:
        rows = conn.execute(
            """
            SELECT ip_address, hostname, status, output, pinged_at
            FROM ping_logs
            WHERE ip_address = ?
            ORDER BY pinged_at DESC
            LIMIT ?
            """,
            (ip_address, limit),
        ).fetchall()
    return [dict(r) for r in rows]

def ping_all_registered_ips() -> None:
    with _db_lock, closing(get_connection()) as conn:
        rows = conn.execute("SELECT id, ip_address FROM ip_registry").fetchall()

    for row in rows:
        ip_address = row["ip_address"]
        hostname = resolve_hostname(ip_address)
        status, output = run_ping(ip_address)
        pinged_at = _now_iso()
        with _db_lock, closing(get_connection()) as conn:
            conn.execute(
                """
                UPDATE ip_registry
                SET hostname = ?, last_ping_at = ?, last_status = ?, last_output = ?
                WHERE id = ?
                """,
                (hostname, pinged_at, status, output, row["id"]),
            )
            _record_ping_log(conn, ip_address, hostname, status, output, pinged_at)
            _prune_old_ping_logs(conn)
            conn.commit()


def infer_segment_24(ip_address: str) -> str:
    parsed_ip = ipaddress.ip_address(ip_address)
    if parsed_ip.version != 4:
        return "IPv6"
    return str(ipaddress.ip_network(f"{ip_address}/24", strict=False))


def normalize_segment_filter(raw_value: str | None) -> str | None:
    if not raw_value:
        return None
    value = raw_value.strip()
    if not value:
        return None

    if value.endswith("/24") and "." not in value:
        octet = value.split("/")[0]
        if octet.isdigit() and 0 <= int(octet) <= 255:
            return f"THIRD_OCTET:{int(octet)}"

    try:
        network = ipaddress.ip_network(value, strict=False)
        if network.version == 4 and network.prefixlen == 24:
            return str(network)
    except ValueError:
        return None

    return None


def get_rows(segment_filter: str | None = None) -> list[dict[str, str | None]]:
    with _db_lock, closing(get_connection()) as conn:
        rows = conn.execute(
            """
            SELECT ip_address, alias, host_name, host_type, location, notes, hostname, last_ping_at, last_status, last_output
            FROM ip_registry
            ORDER BY created_at DESC
            """
        ).fetchall()

    rendered_rows: list[dict[str, str | None]] = []
    for row in rows:
        segment = infer_segment_24(row["ip_address"])
        current = {
            "ip_address": row["ip_address"],
            "alias": row["alias"],
            "host_name": row["host_name"],
            "host_type": row["host_type"],
            "location": row["location"],
            "notes": row["notes"],
            "hostname": row["hostname"],
            "last_ping_at": row["last_ping_at"],
            "last_status": row["last_status"],
            "last_output": row["last_output"],
            "segment": segment,
        }

        if segment_filter:
            if segment_filter.startswith("THIRD_OCTET:"):
                if segment == "IPv6":
                    continue
                third_octet = int(row["ip_address"].split(".")[2])
                requested = int(segment_filter.split(":", maxsplit=1)[1])
                if third_octet != requested:
                    continue
            elif segment != segment_filter:
                continue

        rendered_rows.append(current)
    return rendered_rows


def get_ip_row(ip_address: str) -> dict[str, str | None] | None:
    with _db_lock, closing(get_connection()) as conn:
        row = conn.execute(
            """
            SELECT ip_address, alias, host_name, host_type, location, notes, hostname, last_ping_at, last_status, last_output
            FROM ip_registry WHERE ip_address = ?
            """,
            (ip_address,),
        ).fetchone()
    if row is None:
        return None
    return dict(row)


def get_available_segments() -> list[str]:
    with _db_lock, closing(get_connection()) as conn:
        rows = conn.execute("SELECT ip_address FROM ip_registry").fetchall()
    return sorted({infer_segment_24(row["ip_address"]) for row in rows})


def _render_host_types(current: str | None) -> str:
    options = ['<option value="">-</option>']
    for item in HOST_TYPE_OPTIONS:
        selected = " selected" if current == item else ""
        options.append(f'<option value="{item}"{selected}>{item}</option>')
    return "".join(options)


def _display_name(user: dict[str, str | None]) -> str:
    name = f"{(user.get('first_name') or '').strip()} {(user.get('last_name') or '').strip()}".strip()
    return name or (user.get("username") or "")


def render_login_page(message: str = "", category: str = "success") -> str:
    alert = f'<p class="alert {category}">{html.escape(message)}</p>' if message else ""
    return f"""<!doctype html>
<html lang=\"es\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>Acceso</title><link rel=\"stylesheet\" href=\"/static/style.css\"></head><body class=\"auth-body\">
<main class=\"auth-container\">{alert}
<section class=\"panel auth-panel\"><h1>Iniciar sesión</h1>
<form action=\"/login\" method=\"post\" class=\"form-grid\">
<label>UserID<input type=\"text\" name=\"username\" required></label>
<label>Contraseña<input type=\"password\" name=\"password\" required></label>
<button type=\"submit\">Entrar</button>
</form>
<p class=\"setup-hint\">Si necesitas más usuarios, debe crearlos un administrador desde dentro del sistema.</p>
</section>
</main></body></html>"""


def render_top_nav(user: dict[str, str | None]) -> str:
    role_badge = "ADMIN" if user["role"] == ROLE_ADMIN else "OPERADOR"
    admin_link = "<a class='btn-link' href='/users'>Usuarios</a>" if user["role"] == ROLE_ADMIN else ""
    return (
        "<div class='top-bar'>"
        f"<h1>Registro y monitoreo de IPs <small class='role-badge'>{role_badge}</small></h1>"
        "<div class='nav-actions'>"
        f"<a class='btn-link' href='/profile'>Perfil ({html.escape(_display_name(user))})</a>"
        f"{admin_link}"
        "<form action='/logout' method='post'><button type='submit'>Cerrar sesión</button></form>"
        "</div></div>"
    )


def render_page(
    user: dict[str, str | None],
    message: str = "",
    category: str = "success",
    segment_filter: str | None = None,
    raw_filter: str = "",
) -> str:
    rows = get_rows(segment_filter=segment_filter)
    segments = get_available_segments()
    alert = f'<p class="alert {category}">{html.escape(message)}</p>' if message else ""
    options = ['<option value="">Todos</option>']
    for seg in segments:
        selected = " selected" if segment_filter == seg else ""
        options.append(f'<option value="{html.escape(seg)}"{selected}>{html.escape(seg)}</option>')

    applied_badge = ""
    if segment_filter:
        human_filter = segment_filter.replace("THIRD_OCTET:", "tercer octeto ")
        applied_badge = f'<p class="filter-badge">Filtro aplicado: {html.escape(human_filter)}</p>'
    elif raw_filter:
        applied_badge = '<p class="alert error">Filtro inválido. Usa por ejemplo 192.168.56.0/24 o 56/24.</p>'

    lines = []
    for row in rows:
        details = (
            f"Nombre: {html.escape(row['host_name'] or '-')}<br>"
            f"Tipo: {html.escape(row['host_type'] or '-')}<br>"
            f"Ubicación: {html.escape(row['location'] or '-')}<br>"
            f"Alias: {html.escape(row['alias'] or '-')}"
        )
        lines.append(
            "<tr>"
            f"<td>{html.escape(row['segment'] or '-')}</td>"
            f"<td>{html.escape(row['ip_address'] or '-')}</td>"
            f"<td>{details}</td>"
            f"<td>{html.escape(row['hostname'] or '-')}</td>"
            f"<td>{html.escape(row['last_status'] or 'Sin ejecutar')}</td>"
            f"<td>{html.escape(row['last_ping_at'] or 'Nunca')}</td>"
            f"<td><pre>{html.escape(row['last_output'] or '-')}</pre></td>"
            f"<td><div class='actions'><a class='btn-link' href='/edit?ip={html.escape(row['ip_address'] or '')}'>Editar host</a><a class='btn-link' href='/logs?ip={html.escape(row['ip_address'] or '')}'>Ver registros</a></div></td>"
            "</tr>"
        )

    body_rows = "".join(lines) if lines else '<tr><td colspan="8" class="empty">No hay IPs para el filtro seleccionado</td></tr>'
    register_panel = ""
    if user["role"] in {ROLE_ADMIN, ROLE_OPERATOR}:
        register_panel = """
<section class="panel"><h2>Registrar IP</h2>
<form action="/register" method="post" class="form-grid">
<label>Dirección IP<input type="text" name="ip_address" required></label>
<label>Alias (opcional)<input type="text" name="alias"></label>
<button type="submit">Guardar</button></form></section>
"""

    return f"""<!doctype html>
<html lang=\"es\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>Registro de IPs</title><link rel=\"stylesheet\" href=\"/static/style.css\"></head><body>
<main class=\"container\">{render_top_nav(user)}{alert}{register_panel}
<section class=\"panel\"><div class=\"panel-header\"><h2>IPs registradas</h2>
<form action=\"/ping-now\" method=\"post\"><button type=\"submit\">Ejecutar ping ahora</button></form></div>
<form action=\"/\" method=\"get\" class=\"filter-form\">
<label>Filtrar por segmento (/24)
<input type=\"text\" name=\"segment_text\" value=\"{html.escape(raw_filter)}\" placeholder=\"192.168.56.0/24 o 56/24\"></label>
<label>Segmentos detectados
<select name=\"segment_select\">{''.join(options)}</select></label>
<button type=\"submit\">Aplicar filtro</button>
<a href=\"/\" class=\"btn-link\">Limpiar</a>
</form>{applied_badge}
<table><thead><tr><th>Segmento</th><th>IP</th><th>Detalles host</th><th>Hostname</th><th>Último estado</th><th>Último ping</th><th>Salida</th><th>Acciones</th></tr></thead>
<tbody>{body_rows}</tbody></table></section></main></body></html>"""


def render_edit_page(
    user: dict[str, str | None],
    ip_data: dict[str, str | None],
    message: str = "",
    category: str = "success",
) -> str:
    alert = f'<p class="alert {category}">{html.escape(message)}</p>' if message else ""
    return f"""<!doctype html>
<html lang=\"es\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>Modificar host</title><link rel=\"stylesheet\" href=\"/static/style.css\"></head><body>
<main class=\"container\">{render_top_nav(user)}{alert}
<section class=\"panel edit-panel\">
<form action=\"/edit\" method=\"post\" class=\"form-grid\">
<label>IP
<input type=\"text\" name=\"ip_address\" value=\"{html.escape(ip_data['ip_address'] or '')}\" readonly></label>
<label>NOMBRE
<input type=\"text\" name=\"host_name\" value=\"{html.escape(ip_data['host_name'] or '')}\"></label>
<label>TIPO
<select name=\"host_type\">{_render_host_types(ip_data['host_type'])}</select></label>
<label>UBICACION
<input type=\"text\" name=\"location\" value=\"{html.escape(ip_data['location'] or '')}\"></label>
<label>ALIAS
<input type=\"text\" name=\"alias\" value=\"{html.escape(ip_data['alias'] or '')}\"></label>
<label>DETALLES ADICIONALES
<textarea name=\"notes\" rows=\"4\">{html.escape(ip_data['notes'] or '')}</textarea></label>
<div class=\"actions\">
<button type=\"submit\">Guardar cambios</button>
<a href=\"/\" class=\"btn-link\">Volver</a>
</div>
</form>
</section></main></body></html>"""


def render_profile_page(user: dict[str, str | None], message: str = "", category: str = "success") -> str:
    alert = f'<p class="alert {category}">{html.escape(message)}</p>' if message else ""
    photo_block = ""
    if user.get("photo_url"):
        photo_block = f"<img class='profile-photo' src='{html.escape(user['photo_url'] or '')}' alt='Foto de perfil'>"

    return f"""<!doctype html>
<html lang=\"es\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>Mi perfil</title><link rel=\"stylesheet\" href=\"/static/style.css\"></head><body>
<main class=\"container\">{render_top_nav(user)}{alert}
<section class=\"panel profile-panel">{photo_block}
<form action=\"/profile\" method=\"post\" class=\"form-grid\">
<label>Nombre<input type=\"text\" name=\"first_name\" value=\"{html.escape(user.get('first_name') or '')}\"></label>
<label>Apellido<input type=\"text\" name=\"last_name\" value=\"{html.escape(user.get('last_name') or '')}\"></label>
<label>UserID<input type=\"text\" name=\"username\" minlength=\"3\" value=\"{html.escape(user.get('username') or '')}\" required></label>
<label>URL de foto (opcional)<input type=\"url\" name=\"photo_url\" value=\"{html.escape(user.get('photo_url') or '')}\" placeholder=\"https://...\"></label>
<button type=\"submit\">Actualizar perfil</button>
</form>
</section></main></body></html>"""


def _render_role_options(current: str) -> str:
    return (
        f'<option value="admin"{" selected" if current == ROLE_ADMIN else ""}>Admin</option>'
        f'<option value="operator"{" selected" if current == ROLE_OPERATOR else ""}>Operador</option>'
    )


def render_users_page(current_user: dict[str, str | None], message: str = "", category: str = "success") -> str:
    alert = f'<p class="alert {category}">{html.escape(message)}</p>' if message else ""
    rows = []
    for user in get_all_users():
        rows.append(
            "<tr><td>"
            f"<form action='/users/update' method='post' class='users-grid'>"
            f"<input type='hidden' name='original_username' value='{html.escape(user['username'] or '')}'>"
            f"<input type='text' name='username' value='{html.escape(user['username'] or '')}' required>"
            f"<select name='role'>{_render_role_options(user['role'] or ROLE_OPERATOR)}</select>"
            f"<input type='text' name='first_name' value='{html.escape(user['first_name'] or '')}' placeholder='Nombre'>"
            f"<input type='text' name='last_name' value='{html.escape(user['last_name'] or '')}' placeholder='Apellido'>"
            f"<input type='url' name='photo_url' value='{html.escape(user['photo_url'] or '')}' placeholder='URL foto'>"
            "<input type='password' name='new_password' placeholder='Nueva contraseña (opcional)'>"
            "<button type='submit'>Guardar</button></form></td><td>"
            f"<form action='/users/delete' method='post'><input type='hidden' name='username' value='{html.escape(user['username'] or '')}'><button type='submit'>Eliminar</button></form>"
            "</td></tr>"
        )

    body_rows = "".join(rows) if rows else "<tr><td colspan='2'>No hay usuarios</td></tr>"

    return f"""<!doctype html>
<html lang=\"es\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>Gestión de usuarios</title><link rel=\"stylesheet\" href=\"/static/style.css\"></head><body>
<main class=\"container\">{render_top_nav(current_user)}{alert}
<section class=\"panel"><h2>Crear usuario</h2>
<form action=\"/users/create\" method=\"post\" class=\"form-grid\">
<label>UserID<input type=\"text\" name=\"username\" minlength=\"3\" required></label>
<label>Contraseña<input type=\"password\" name=\"password\" minlength=\"4\" required></label>
<label>Rol
<select name=\"role\"><option value=\"operator\">Operador</option><option value=\"admin\">Admin</option></select></label>
<label>Nombre<input type=\"text\" name=\"first_name\"></label>
<label>Apellido<input type=\"text\" name=\"last_name\"></label>
<label>URL de foto<input type=\"url\" name=\"photo_url\"></label>
<button type=\"submit\">Crear usuario</button>
</form>
</section>
<section class=\"panel"><h2>Lista de usuarios</h2>
<table><thead><tr><th>Edición</th><th>Acción</th></tr></thead><tbody>{body_rows}</tbody></table>
</section>
</main></body></html>"""




def render_ping_logs_page(user: dict[str, str | None], ip_address: str) -> str:
    logs = get_ping_logs_for_ip(ip_address)
    rows = []
    for item in logs:
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['pinged_at'] or '-')}</td>"
            f"<td>{html.escape(item['status'] or '-')}</td>"
            f"<td>{html.escape(item['hostname'] or '-')}</td>"
            f"<td><pre>{html.escape(item['output'] or '-')}</pre></td>"
            "</tr>"
        )

    body_rows = "".join(rows) if rows else "<tr><td colspan='4' class='empty'>Sin registros de ping para esta IP</td></tr>"
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Registros de ping</title><link rel="stylesheet" href="/static/style.css"></head><body>
<main class="container">{render_top_nav(user)}
<section class="panel"><h2>Historial de ping (últimos {PING_LOG_RETENTION_DAYS} días) - {html.escape(ip_address)}</h2>
<a href="/" class="btn-link">Volver</a>
<table><thead><tr><th>Fecha</th><th>Estado</th><th>Hostname</th><th>Salida</th></tr></thead><tbody>{body_rows}</tbody></table>
</section>
</main></body></html>"""

class Handler(BaseHTTPRequestHandler):
    def _require_auth_user(self) -> dict[str, str | None] | None:
        username = _read_session_username(self.headers)
        if not username:
            return None
        return get_user_by_username(username)

    def _redirect(self, location: str, cookie: str | None = None) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)

        if parsed.path.startswith("/static/"):
            static_path = Path(parsed.path.lstrip("/"))
            if not static_path.exists() or not static_path.is_file():
                self.send_error(404)
                return
            content = static_path.read_bytes()
            ctype, _ = mimetypes.guess_type(static_path.name)
            self.send_response(200)
            self.send_header("Content-Type", ctype or "application/octet-stream")
            self.end_headers()
            self.wfile.write(content)
            return

        user = self._require_auth_user()

        if parsed.path == "/login":
            if user:
                self._redirect("/")
            else:
                self._respond_html(render_login_page())
            return

        if not user:
            self._redirect("/login")
            return

        if parsed.path == "/":
            query = parse_qs(parsed.query)
            text = query.get("segment_text", [""])[0].strip()
            pick = query.get("segment_select", [""])[0].strip()
            raw_filter = text or pick
            segment_filter = normalize_segment_filter(raw_filter)
            self._respond_html(render_page(user=user, segment_filter=segment_filter, raw_filter=raw_filter))
            return

        if parsed.path == "/edit":
            query = parse_qs(parsed.query)
            ip_address = query.get("ip", [""])[0]
            ip_data = get_ip_row(ip_address)
            if ip_data is None:
                self._respond_html(render_page(user=user, message="IP no encontrada", category="error"))
            else:
                self._respond_html(render_edit_page(user=user, ip_data=ip_data))
            return

        if parsed.path == "/logs":
            query = parse_qs(parsed.query)
            ip_address = query.get("ip", [""])[0]
            ip_data = get_ip_row(ip_address)
            if ip_data is None:
                self._respond_html(render_page(user=user, message="IP no encontrada", category="error"))
            else:
                self._respond_html(render_ping_logs_page(user=user, ip_address=ip_address))
            return

        if parsed.path == "/profile":
            self._respond_html(render_profile_page(user=user))
            return

        if parsed.path == "/users":
            if user["role"] != ROLE_ADMIN:
                self._respond_html(render_page(user=user, message="Solo admin puede gestionar usuarios", category="error"))
                return
            self._respond_html(render_users_page(user))
            return

        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        form = parse_qs(raw)

        if parsed.path == "/login":
            username = form.get("username", [""])[0]
            password = form.get("password", [""])[0]
            if not authenticate_user(username, password):
                self._respond_html(render_login_page("Credenciales inválidas", "error"))
                return
            cookie_value = _build_session_cookie(username.strip())
            self._redirect("/", cookie=f"{AUTH_COOKIE_NAME}={cookie_value}; Path=/; HttpOnly; SameSite=Lax")
            return

        if parsed.path == "/logout":
            self._redirect("/login", cookie=f"{AUTH_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
            return

        user = self._require_auth_user()
        if not user:
            self._redirect("/login")
            return

        if parsed.path == "/profile":
            new_username = form.get("username", [""])[0]
            first_name = form.get("first_name", [""])[0]
            last_name = form.get("last_name", [""])[0]
            photo_url = form.get("photo_url", [""])[0]
            ok, msg, resulting_username = update_profile(
                current_username=user["username"] or "",
                new_username=new_username,
                first_name=first_name,
                last_name=last_name,
                photo_url=photo_url,
            )
            refreshed = get_user_by_username(resulting_username)
            if refreshed is None:
                self._redirect("/login")
                return
            if ok:
                cookie_value = _build_session_cookie(resulting_username)
                self.send_response(200)
                self.send_header("Set-Cookie", f"{AUTH_COOKIE_NAME}={cookie_value}; Path=/; HttpOnly; SameSite=Lax")
                body = render_profile_page(refreshed, msg, "success").encode("utf-8")
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self._respond_html(render_profile_page(user, msg, "error"))
            return

        if parsed.path == "/register":
            if user["role"] not in {ROLE_ADMIN, ROLE_OPERATOR}:
                self._respond_html(render_page(user=user, message="No tienes permisos para registrar IPs", category="error"))
                return
            ip_address = form.get("ip_address", [""])[0]
            alias = form.get("alias", [""])[0]
            ok, msg = register_ip(ip_address, alias)
            self._respond_html(render_page(user=user, message=msg, category="success" if ok else "error"))
            return

        if parsed.path == "/ping-now":
            ping_all_registered_ips()
            self._respond_html(render_page(user=user, message="Ping manual ejecutado", category="success"))
            return

        if parsed.path == "/edit":
            ip_address = form.get("ip_address", [""])[0]
            host_name = form.get("host_name", [""])[0]
            host_type = form.get("host_type", [""])[0]
            location = form.get("location", [""])[0]
            notes = form.get("notes", [""])[0]
            alias = form.get("alias", [""])[0]
            ok, msg = update_host_details(ip_address, host_name, host_type, location, notes, alias)
            ip_data = get_ip_row(ip_address)
            if ip_data is None:
                self._respond_html(render_page(user=user, message="IP no encontrada", category="error"))
            else:
                self._respond_html(render_edit_page(user=user, ip_data=ip_data, message=msg, category="success" if ok else "error"))
            return

        if parsed.path.startswith("/users"):
            if user["role"] != ROLE_ADMIN:
                self._respond_html(render_page(user=user, message="Solo admin puede gestionar usuarios", category="error"))
                return

            if parsed.path == "/users/create":
                ok, msg = create_user_by_admin(
                    username=form.get("username", [""])[0],
                    password=form.get("password", [""])[0],
                    role=form.get("role", [ROLE_OPERATOR])[0],
                    first_name=form.get("first_name", [""])[0],
                    last_name=form.get("last_name", [""])[0],
                    photo_url=form.get("photo_url", [""])[0],
                )
                self._respond_html(render_users_page(user, msg, "success" if ok else "error"))
                return

            if parsed.path == "/users/update":
                original_username = form.get("original_username", [""])[0]
                ok, msg = admin_update_user(
                    original_username=original_username,
                    new_username=form.get("username", [""])[0],
                    role=form.get("role", [ROLE_OPERATOR])[0],
                    first_name=form.get("first_name", [""])[0],
                    last_name=form.get("last_name", [""])[0],
                    photo_url=form.get("photo_url", [""])[0],
                    new_password=form.get("new_password", [""])[0],
                )
                if original_username == user["username"]:
                    refreshed = get_user_by_username(form.get("username", [""])[0].strip())
                    if refreshed:
                        user = refreshed
                        cookie_value = _build_session_cookie(user["username"] or "")
                        self.send_response(200)
                        self.send_header("Set-Cookie", f"{AUTH_COOKIE_NAME}={cookie_value}; Path=/; HttpOnly; SameSite=Lax")
                        body = render_users_page(user, msg, "success" if ok else "error").encode("utf-8")
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return
                self._respond_html(render_users_page(user, msg, "success" if ok else "error"))
                return

            if parsed.path == "/users/delete":
                target = form.get("username", [""])[0]
                ok, msg = admin_delete_user(target, acting_username=user["username"] or "")
                self._respond_html(render_users_page(user, msg, "success" if ok else "error"))
                return

        self.send_error(404)

    def _respond_html(self, html_body: str) -> None:
        data = html_body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def scheduler_loop(stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        ping_all_registered_ips()
        stop_event.wait(PING_INTERVAL_SECONDS)


def run() -> None:
    init_db()
    stop_event = threading.Event()
    threading.Thread(target=scheduler_loop, args=(stop_event,), daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Servidor en http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        server.server_close()


if __name__ == "__main__":
    run()
