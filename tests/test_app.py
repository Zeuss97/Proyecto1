import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app


def setup_module():
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.close()
    app.DB_PATH = Path(tmp.name)
    app.init_db()


def test_demo_admin_exists_by_default():
    assert app.authenticate_user("admin", "admin") is True
    admin = app.get_user_by_username("admin")
    assert admin is not None
    assert admin["role"] == app.ROLE_ADMIN


def test_admin_can_create_and_delete_operator():
    ok, msg = app.create_user_by_admin("operador1", "secreto", "operator", "Ope", "Uno", "")
    assert ok is True
    assert "creado" in msg
    assert app.authenticate_user("operador1", "secreto") is True

    ok_del, msg_del = app.admin_delete_user("operador1", acting_username="admin")
    assert ok_del is True
    assert "eliminado" in msg_del


def test_operator_cannot_delete_self_logic_guard():
    app.create_user_by_admin("operador2", "secreto", "operator")
    ok, msg = app.admin_delete_user("operador2", acting_username="operador2")
    assert ok is False
    assert "propio" in msg


def test_profile_can_change_username_and_names():
    app.create_user_by_admin("operador3", "secreto", "operator")
    ok, msg, new_username = app.update_profile("operador3", "ope3", "Ana", "Gomez", "https://example.com/a.jpg")
    assert ok is True
    assert "actualizado" in msg
    assert new_username == "ope3"

    row = app.get_user_by_username("ope3")
    assert row is not None
    assert row["first_name"] == "Ana"
    assert row["last_name"] == "Gomez"



def test_ping_logs_saved_and_pruned():
    app.register_ip("10.0.0.50", "imp")

    with app.get_connection() as conn:
        recent = app._now_iso()
        old = "2000-01-01T00:00:00+00:00"
        app._record_ping_log(conn, "10.0.0.50", "host-a", "OK", "todo bien", recent)
        app._record_ping_log(conn, "10.0.0.50", "host-a", "ERROR", "sin respuesta", old)
        app._prune_old_ping_logs(conn)
        conn.commit()

    logs = app.get_ping_logs_for_ip("10.0.0.50")
    assert len(logs) == 1
    assert logs[0]["status"] == "OK"

def test_invalid_ip_is_rejected():
    ok, msg = app.register_ip("not-an-ip", "x")
    assert ok is False
    assert "válida" in msg


def test_register_ip_and_ping():
    ok, _ = app.register_ip("127.0.0.1", "local")
    assert ok is True
    app.ping_all_registered_ips()

    with app.get_connection() as conn:
        row = conn.execute("SELECT last_status, last_ping_at FROM ip_registry WHERE ip_address = ?", ("127.0.0.1",)).fetchone()

    assert row is not None
    assert row["last_status"] in {"OK", "ERROR"}
    assert row["last_ping_at"] is not None


def test_segment_filter_supports_short_and_cidr_formats():
    app.register_ip("192.168.56.10", "seg56")
    app.register_ip("192.168.59.20", "seg59")

    short_filter = app.normalize_segment_filter("56/24")
    cidr_filter = app.normalize_segment_filter("192.168.59.0/24")

    short_rows = app.get_rows(segment_filter=short_filter)
    cidr_rows = app.get_rows(segment_filter=cidr_filter)

    assert short_filter == "THIRD_OCTET:56"
    assert cidr_filter == "192.168.59.0/24"
    assert any(r["ip_address"] == "192.168.56.10" for r in short_rows)
    assert all(r["segment"] == "192.168.59.0/24" for r in cidr_rows)


def test_host_details_can_be_updated():
    app.register_ip("192.168.60.15", "sin-detalles")
    ok, msg = app.update_host_details(
        ip_address="192.168.60.15",
        host_name="PABLO RIVEROS",
        host_type="NOTEBOOK",
        location="INF",
        notes="Equipo de pruebas",
        alias="PABLO",
    )

    assert ok is True
    assert "actualizado" in msg

    row = app.get_ip_row("192.168.60.15")
    assert row is not None
    assert row["host_name"] == "PABLO RIVEROS"
    assert row["host_type"] == "NOTEBOOK"
    assert row["location"] == "INF"
    assert row["notes"] == "Equipo de pruebas"


def test_format_last_ping_shows_datetime_without_timezone_suffix():
    assert app._format_last_ping("2026-02-17T19:13:33.491648+00:00") == "2026-02-17 19:13:33"
    assert app._format_last_ping(None) == "Nunca"
