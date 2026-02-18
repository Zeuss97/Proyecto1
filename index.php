<?php

declare(strict_types=1);

const DB_DIR = __DIR__ . '/data';
const DB_PATH = DB_DIR . '/ips.db';
const ROLE_ADMIN = 'admin';
const ROLE_OPERATOR = 'operator';
const HOST_TYPES = ['NOTEBOOK', 'DESKTOP', 'SERVER', 'IMPRESORA', 'ROUTER', 'OTRO'];
const DISPLAY_TZ = '-03:00';

session_start();

date_default_timezone_set('UTC');

function ensure_db_directory(): void
{
    if (!is_dir(DB_DIR)) {
        mkdir(DB_DIR, 0775, true);
    }
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    ensure_db_directory();
    $pdo = new PDO('sqlite:' . DB_PATH);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    return $pdo;
}

function now_iso(): string
{
    return (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format(DateTimeInterface::ATOM);
}

function format_display_datetime(?string $value): string
{
    $raw = trim((string) $value);
    if ($raw === '') {
        return '-';
    }

    try {
        $date = new DateTimeImmutable($raw);
        $displayTz = new DateTimeZone(DISPLAY_TZ);
        return $date->setTimezone($displayTz)->format('d.m.Y H:i:s');
    } catch (Exception) {
        return $raw;
    }
}

function init_db(): void
{
    $pdo = db();
    $pdo->exec('CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT "operator",
        first_name TEXT,
        last_name TEXT,
        created_at TEXT NOT NULL
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS ip_registry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL UNIQUE,
        alias TEXT,
        host_name TEXT,
        host_type TEXT,
        location TEXT,
        notes TEXT,
        last_ping_at TEXT,
        last_status TEXT,
        last_output TEXT,
        created_at TEXT NOT NULL,
        created_by TEXT
    )');

    $columns = $pdo->query('PRAGMA table_info(ip_registry)')->fetchAll();
    $columnNames = array_column($columns, 'name');
    if (!in_array('created_by', $columnNames, true)) {
        $pdo->exec('ALTER TABLE ip_registry ADD COLUMN created_by TEXT');
    }

    $pdo->exec('CREATE TABLE IF NOT EXISTS ping_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        hostname TEXT,
        status TEXT NOT NULL,
        output TEXT,
        pinged_at TEXT NOT NULL
    )');

    $stmt = $pdo->prepare('SELECT 1 FROM users WHERE username = :username');
    $stmt->execute(['username' => 'admin']);
    if (!$stmt->fetchColumn()) {
        $insert = $pdo->prepare('INSERT INTO users (username, password_hash, role, first_name, last_name, created_at)
            VALUES (:username, :password_hash, :role, :first_name, :last_name, :created_at)');
        $insert->execute([
            'username' => 'admin',
            'password_hash' => password_hash('admin', PASSWORD_DEFAULT),
            'role' => ROLE_ADMIN,
            'first_name' => 'Admin',
            'last_name' => 'Demo',
            'created_at' => now_iso(),
        ]);
    }
}

function current_user(): ?array
{
    if (empty($_SESSION['username'])) {
        return null;
    }

    $stmt = db()->prepare('SELECT username, role, first_name, last_name FROM users WHERE username = :username');
    $stmt->execute(['username' => $_SESSION['username']]);
    return $stmt->fetch() ?: null;
}

function flash(?string $message = null, string $type = 'info'): ?array
{
    if ($message !== null) {
        $_SESSION['flash'] = ['message' => $message, 'type' => $type];
        return null;
    }

    if (!isset($_SESSION['flash'])) {
        return null;
    }

    $data = $_SESSION['flash'];
    unset($_SESSION['flash']);
    return $data;
}

function redirect(string $url): never
{
    header('Location: ' . $url);
    exit;
}

function h(?string $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

function validate_ip(string $ip): bool
{
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

function normalize_segment_filter(string $input): ?string
{
    $raw = trim($input);
    if ($raw === '') {
        return null;
    }

    if (preg_match('/^\d{1,3}$/', $raw)) {
        $octet = (int) $raw;
        if ($octet >= 0 && $octet <= 255) {
            return 'THIRD_OCTET:' . $octet;
        }
    }

    if (preg_match('/^(\d{1,3})\/24$/', $raw, $m)) {
        $octet = (int) $m[1];
        if ($octet >= 0 && $octet <= 255) {
            return 'THIRD_OCTET:' . $octet;
        }
    }

    if (preg_match('/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.0\/24$/', $raw, $m)) {
        foreach ([1, 2, 3] as $idx) {
            $value = (int) $m[$idx];
            if ($value < 0 || $value > 255) {
                return null;
            }
        }
        return sprintf('%d.%d.%d.0/24', $m[1], $m[2], $m[3]);
    }

    return null;
}

function compute_segment(string $ip): string
{
    $parts = explode('.', $ip);
    if (count($parts) === 4) {
        return sprintf('%s.%s.%s.0/24', $parts[0], $parts[1], $parts[2]);
    }
    return '-';
}

function parse_hostname_from_output(string $output): ?string
{
    $lines = preg_split('/\R/', $output) ?: [];
    foreach ($lines as $line) {
        if (preg_match('/Pinging\s+(.+?)\s*\[/', $line, $m)) {
            return trim($m[1]);
        }
        if (preg_match('/PING\s+([^\s(]+)/', $line, $m)) {
            return trim($m[1]);
        }
    }
    return null;
}

function ping_ip(string $ip): array
{
    $isWindows = strtoupper(substr(PHP_OS_FAMILY, 0, 3)) === 'WIN';
    $command = $isWindows ? sprintf('ping -a -n 1 %s', escapeshellarg($ip)) : sprintf('ping -c 1 %s', escapeshellarg($ip));

    $outputLines = [];
    $exitCode = 1;
    @exec($command . ' 2>&1', $outputLines, $exitCode);

    $output = trim(implode(PHP_EOL, $outputLines));
    $hostname = parse_hostname_from_output($output);
    if ($hostname === null) {
        $resolved = @gethostbyaddr($ip);
        if ($resolved !== false && $resolved !== $ip) {
            $hostname = $resolved;
        }
    }

    return [
        'status' => $exitCode === 0 ? 'OK' : 'ERROR',
        'hostname' => $hostname,
        'output' => $output,
    ];
}

function run_ping_for_ip(string $ip): void
{
    $result = ping_ip($ip);
    $timestamp = now_iso();

    $update = db()->prepare('UPDATE ip_registry
        SET last_ping_at = :last_ping_at, last_status = :last_status, last_output = :last_output,
            host_name = COALESCE(NULLIF(host_name, ""), :host_name)
        WHERE ip_address = :ip_address');
    $update->execute([
        'last_ping_at' => $timestamp,
        'last_status' => $result['status'],
        'last_output' => $result['output'],
        'host_name' => $result['hostname'],
        'ip_address' => $ip,
    ]);

    $insert = db()->prepare('INSERT INTO ping_logs (ip_address, hostname, status, output, pinged_at)
        VALUES (:ip_address, :hostname, :status, :output, :pinged_at)');
    $insert->execute([
        'ip_address' => $ip,
        'hostname' => $result['hostname'],
        'status' => $result['status'],
        'output' => $result['output'],
        'pinged_at' => $timestamp,
    ]);

    $prune = db()->prepare('DELETE FROM ping_logs WHERE pinged_at < :limit');
    $limit = (new DateTimeImmutable('now', new DateTimeZone('UTC')))->sub(new DateInterval('P7D'))->format(DateTimeInterface::ATOM);
    $prune->execute(['limit' => $limit]);
}

function list_wallpapers(): array
{
    $dir = __DIR__ . '/wallpaper';
    if (!is_dir($dir)) {
        return [];
    }

    $paths = glob($dir . '/*.{jpg,jpeg,png,webp,gif}', GLOB_BRACE) ?: [];
    sort($paths);

    return array_map(static fn(string $path): string => 'wallpaper/' . basename($path), $paths);
}

init_db();

$action = $_POST['action'] ?? $_GET['action'] ?? null;
$user = current_user();

if ($action === 'login') {
    $username = trim((string) ($_POST['username'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');

    $stmt = db()->prepare('SELECT username, password_hash FROM users WHERE username = :username');
    $stmt->execute(['username' => $username]);
    $row = $stmt->fetch();

    if ($row && password_verify($password, $row['password_hash'])) {
        $_SESSION['username'] = $row['username'];
        flash('Bienvenido, ' . $row['username'] . '.', 'success');
    } else {
        flash('Credenciales inválidas.', 'error');
    }
    redirect('index.php');
}

if ($action === 'logout') {
    session_destroy();
    session_start();
    flash('Sesión cerrada.', 'info');
    redirect('index.php');
}

if ($user === null) {
    $flash = flash();
    $wallpaper = trim((string) ($_SESSION['wallpaper'] ?? ''));
    $allowedWallpapers = list_wallpapers();
    $loginWallpaper = in_array($wallpaper, $allowedWallpapers, true) ? $wallpaper : '';
    ?>
    <!doctype html>
    <html lang="es">
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>IP Checker · Login</title>
        <link rel="stylesheet" href="static/style.css" />
        <?php if ($loginWallpaper !== ''): ?>
            <style>
                body::before { background-image: url('<?= h($loginWallpaper) ?>'); }
            </style>
        <?php endif; ?>
    </head>
    <body class="login-page">
    <main class="login-card">
        <h1>IP Checker</h1>
        <p>Inicia sesión para administrar el monitoreo.</p>
        <?php if ($flash): ?>
            <div class="flash <?= h($flash['type']) ?>"><?= h($flash['message']) ?></div>
        <?php endif; ?>
        <form method="post" class="form-grid single">
            <input type="hidden" name="action" value="login" />
            <label>
                Usuario
                <input type="text" name="username" required />
            </label>
            <label>
                Contraseña
                <input type="password" name="password" required />
            </label>
            <button type="submit" class="btn primary">Entrar</button>
        </form>
        <small>Demo: admin / admin</small>
    </main>
    </body>
    </html>
    <?php
    exit;
}

if ($action === 'set_wallpaper') {
    $choice = trim((string) ($_POST['wallpaper'] ?? ''));
    $allowed = list_wallpapers();
    if ($choice === '' || in_array($choice, $allowed, true)) {
        $_SESSION['wallpaper'] = $choice;
    }
    redirect('index.php');
}

if ($action === 'toggle_theme') {
    $_SESSION['theme'] = (($_SESSION['theme'] ?? 'light') === 'light') ? 'dark' : 'light';
    redirect('index.php');
}

if ($action === 'add_ip') {
    if ($user['role'] !== ROLE_ADMIN) {
        flash('Solo admin puede registrar IPs.', 'error');
        redirect('index.php');
    }

    $ip = trim((string) ($_POST['ip_address'] ?? ''));
    if (!validate_ip($ip)) {
        flash('La IP no es válida.', 'error');
        redirect('index.php');
    }

    $alias = trim((string) ($_POST['alias'] ?? ''));
    $location = trim((string) ($_POST['location'] ?? ''));

    try {
        $stmt = db()->prepare('INSERT INTO ip_registry (ip_address, alias, location, created_at, created_by)
            VALUES (:ip_address, :alias, :location, :created_at, :created_by)');
        $stmt->execute([
            'ip_address' => $ip,
            'alias' => $alias,
            'location' => $location,
            'created_at' => now_iso(),
            'created_by' => $user['username'],
        ]);
        flash('IP registrada.', 'success');
    } catch (PDOException) {
        flash('La IP ya existe.', 'error');
    }
    redirect('index.php?view=ips');
}

if ($action === 'save_ip') {
    $ip = trim((string) ($_POST['ip_address'] ?? ''));
    if (!validate_ip($ip)) {
        flash('IP inválida.', 'error');
        redirect('index.php');
    }

    $stmt = db()->prepare('UPDATE ip_registry
        SET alias = :alias, host_name = :host_name, host_type = :host_type, location = :location, notes = :notes
        WHERE ip_address = :ip_address');
    $stmt->execute([
        'alias' => trim((string) ($_POST['alias'] ?? '')),
        'host_name' => trim((string) ($_POST['host_name'] ?? '')),
        'host_type' => trim((string) ($_POST['host_type'] ?? '')),
        'location' => trim((string) ($_POST['location'] ?? '')),
        'notes' => trim((string) ($_POST['notes'] ?? '')),
        'ip_address' => $ip,
    ]);
    flash('Datos actualizados.', 'success');
    redirect('index.php?view=ips');
}

if ($action === 'add_user') {
    if ($user['role'] !== ROLE_ADMIN) {
        flash('Solo admin puede crear usuarios.', 'error');
        redirect('index.php');
    }

    $username = trim((string) ($_POST['username'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');
    $role = trim((string) ($_POST['role'] ?? ROLE_OPERATOR));
    $firstName = trim((string) ($_POST['first_name'] ?? ''));
    $lastName = trim((string) ($_POST['last_name'] ?? ''));

    if ($username === '' || $password === '') {
        flash('Usuario y contraseña son obligatorios.', 'error');
        redirect('index.php');
    }

    if (!in_array($role, [ROLE_ADMIN, ROLE_OPERATOR], true)) {
        $role = ROLE_OPERATOR;
    }

    try {
        $stmt = db()->prepare('INSERT INTO users (username, password_hash, role, first_name, last_name, created_at)
            VALUES (:username, :password_hash, :role, :first_name, :last_name, :created_at)');
        $stmt->execute([
            'username' => $username,
            'password_hash' => password_hash($password, PASSWORD_DEFAULT),
            'role' => $role,
            'first_name' => $firstName,
            'last_name' => $lastName,
            'created_at' => now_iso(),
        ]);
        flash('Usuario creado correctamente.', 'success');
    } catch (PDOException) {
        flash('No se pudo crear el usuario (usuario ya existe).', 'error');
    }
    redirect('index.php');
}

if ($action === 'update_user') {
    if ($user['role'] !== ROLE_ADMIN) {
        flash('Solo admin puede modificar usuarios.', 'error');
        redirect('index.php');
    }

    $username = trim((string) ($_POST['username'] ?? ''));
    $role = trim((string) ($_POST['role'] ?? ROLE_OPERATOR));
    $firstName = trim((string) ($_POST['first_name'] ?? ''));
    $lastName = trim((string) ($_POST['last_name'] ?? ''));
    $newPassword = (string) ($_POST['new_password'] ?? '');

    if ($username === '') {
        flash('Debe seleccionar un usuario.', 'error');
        redirect('index.php?modal=edit_user');
    }

    if (!in_array($role, [ROLE_ADMIN, ROLE_OPERATOR], true)) {
        $role = ROLE_OPERATOR;
    }

    $stmt = db()->prepare('UPDATE users SET role = :role, first_name = :first_name, last_name = :last_name WHERE username = :username');
    $stmt->execute([
        'role' => $role,
        'first_name' => $firstName,
        'last_name' => $lastName,
        'username' => $username,
    ]);

    if ($newPassword !== '') {
        $passStmt = db()->prepare('UPDATE users SET password_hash = :password_hash WHERE username = :username');
        $passStmt->execute([
            'password_hash' => password_hash($newPassword, PASSWORD_DEFAULT),
            'username' => $username,
        ]);
    }

    flash('Usuario modificado correctamente.', 'success');
    redirect('index.php');
}

if ($action === 'reset_user_password') {
    if ($user['role'] !== ROLE_ADMIN) {
        flash('Solo admin puede recuperar contraseñas.', 'error');
        redirect('index.php');
    }

    $username = trim((string) ($_POST['username'] ?? ''));
    $newPassword = (string) ($_POST['new_password'] ?? '');

    if ($username === '' || $newPassword === '') {
        flash('Usuario y nueva contraseña son obligatorios.', 'error');
        redirect('index.php?modal=reset_password');
    }

    $stmt = db()->prepare('UPDATE users SET password_hash = :password_hash WHERE username = :username');
    $stmt->execute([
        'password_hash' => password_hash($newPassword, PASSWORD_DEFAULT),
        'username' => $username,
    ]);

    flash('Contraseña actualizada correctamente.', 'success');
    redirect('index.php');
}

if ($action === 'ping_now') {
    $ip = trim((string) ($_POST['ip_address'] ?? ''));
    if (validate_ip($ip)) {
        run_ping_for_ip($ip);
        flash('Ping ejecutado para ' . $ip . '.', 'success');
    }
    redirect('index.php?view=ips');
}

if ($action === 'ping_all') {
    $rows = db()->query('SELECT ip_address FROM ip_registry ORDER BY ip_address')->fetchAll();
    foreach ($rows as $row) {
        run_ping_for_ip($row['ip_address']);
    }
    flash('Ping manual ejecutado para todas las IPs.', 'success');
    redirect('index.php?view=ips');
}

$segmentFilterInput = trim((string) ($_GET['segment'] ?? ''));
$segmentFilter = normalize_segment_filter($segmentFilterInput);
$ipFilterInput = trim((string) ($_GET['ip_filter'] ?? ''));
$nameFilterInput = trim((string) ($_GET['name_filter'] ?? ''));
$locationFilterInput = trim((string) ($_GET['location_filter'] ?? ''));

$sql = 'SELECT * FROM ip_registry';
$params = [];
$conditions = [];
if ($segmentFilter !== null) {
    if (str_starts_with($segmentFilter, 'THIRD_OCTET:')) {
        $octet = (int) substr($segmentFilter, strlen('THIRD_OCTET:'));
        $conditions[] = 'CAST(substr(ip_address, instr(ip_address, ".") + instr(substr(ip_address, instr(ip_address, ".") + 1), ".") + 1, instr(substr(ip_address, instr(ip_address, ".") + instr(substr(ip_address, instr(ip_address, ".") + 1), ".") + 1), ".") -1 ) AS INTEGER) = :octet';
        $params['octet'] = $octet;
    } else {
        [$a, $b, $c] = explode('.', explode('.0/24', $segmentFilter)[0]);
        $prefix = sprintf('%s.%s.%s.', $a, $b, $c);
        $conditions[] = 'ip_address LIKE :prefix';
        $params['prefix'] = $prefix . '%';
    }
}

if ($ipFilterInput !== '') {
    $conditions[] = 'ip_address LIKE :ip_filter';
    $params['ip_filter'] = '%' . $ipFilterInput . '%';
}

if ($nameFilterInput !== '') {
    $conditions[] = '(host_name LIKE :name_filter OR alias LIKE :name_filter)';
    $params['name_filter'] = '%' . $nameFilterInput . '%';
}

if ($locationFilterInput !== '') {
    $conditions[] = 'location LIKE :location_filter';
    $params['location_filter'] = '%' . $locationFilterInput . '%';
}

if ($conditions) {
    $sql .= ' WHERE ' . implode(' AND ', $conditions);
}
$sql .= ' ORDER BY ip_address';
$stmt = db()->prepare($sql);
$stmt->execute($params);
$rows = $stmt->fetchAll();

foreach ($rows as &$row) {
    $row['segment'] = compute_segment($row['ip_address']);
}
unset($row);

$allIpRows = db()->query('SELECT ip_address FROM ip_registry ORDER BY ip_address')->fetchAll();
$segmentStatsMap = [];
foreach ($allIpRows as $ipRow) {
    $segment = compute_segment($ipRow['ip_address']);
    if (!isset($segmentStatsMap[$segment])) {
        $segmentStatsMap[$segment] = ['segment' => $segment, 'used' => 0, 'free' => 254];
    }
    $segmentStatsMap[$segment]['used']++;
}
foreach ($segmentStatsMap as &$segmentData) {
    $segmentData['free'] = max(0, 254 - $segmentData['used']);
}
unset($segmentData);
$segmentStats = array_values($segmentStatsMap);
usort($segmentStats, static fn(array $a, array $b): int => strcmp($a['segment'], $b['segment']));

$dashboardSegment = trim((string) ($_GET['dashboard_segment'] ?? ''));
if ($dashboardSegment === '' && $segmentStats) {
    $dashboardSegment = $segmentStats[0]['segment'];
}

$dashboardData = ['segment' => $dashboardSegment, 'used' => 0, 'free' => 254];
foreach ($segmentStats as $seg) {
    if ($seg['segment'] === $dashboardSegment) {
        $dashboardData = $seg;
        break;
    }
}

$dashboardUsedPct = min(100, max(0, (int) round(($dashboardData['used'] / 254) * 100)));
$dashboardSegmentOctet = '';
if ($dashboardData['segment'] !== '' && str_contains($dashboardData['segment'], '.')) {
    $parts = explode('.', $dashboardData['segment']);
    if (isset($parts[2])) {
        $dashboardSegmentOctet = $parts[2];
    }
}

$detailIp = trim((string) ($_GET['ip'] ?? ''));
$detail = null;
$history = [];
if (($action === 'detail' || isset($_GET['ip'])) && validate_ip($detailIp)) {
    $stmt = db()->prepare('SELECT * FROM ip_registry WHERE ip_address = :ip_address');
    $stmt->execute(['ip_address' => $detailIp]);
    $detail = $stmt->fetch() ?: null;

    if ($detail) {
        $historyStmt = db()->prepare('SELECT pinged_at, status, COALESCE(hostname, "-") AS hostname
            FROM ping_logs WHERE ip_address = :ip_address ORDER BY pinged_at DESC LIMIT 100');
        $historyStmt->execute(['ip_address' => $detailIp]);
        $history = $historyStmt->fetchAll();
    }
}

$flash = flash();
$wallpapers = list_wallpapers();
$selectedWallpaper = $_SESSION['wallpaper'] ?? '';
$theme = $_SESSION['theme'] ?? 'light';
$displayName = trim(($user['first_name'] ?? '') . ' ' . ($user['last_name'] ?? '')) ?: $user['username'];
$usersList = [];
if ($user['role'] === ROLE_ADMIN) {
    $usersList = db()->query('SELECT username, role, first_name, last_name FROM users ORDER BY username')->fetchAll();
}
$modal = trim((string) ($_GET['modal'] ?? ''));
$showCreateUserModal = $user['role'] === ROLE_ADMIN && $modal === 'create_user';
$showEditUserModal = $user['role'] === ROLE_ADMIN && $modal === 'edit_user';
$showResetPasswordModal = $user['role'] === ROLE_ADMIN && $modal === 'reset_password';
$showListUsersModal = $user['role'] === ROLE_ADMIN && $modal === 'list_users';
$view = trim((string) ($_GET['view'] ?? 'dashboard'));
if (!in_array($view, ['dashboard', 'ips'], true)) {
    $view = 'dashboard';
}
?>
<!doctype html>
<html lang="es" data-theme="<?= h($theme) ?>">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Registro y monitoreo de IPs</title>
    <link rel="stylesheet" href="static/style.css" />
</head>
<body>
<main class="container">
    <header class="topbar">
        <div>
            <h1>Registro y monitoreo de IPs</h1>
            <span class="badge"><?= h(strtoupper($user['role'])) ?></span>
        </div>
        <div class="top-actions">
            <span class="pill">Perfil (<?= h($displayName) ?>)</span>
            <form method="post"><input type="hidden" name="action" value="toggle_theme"><button class="btn">Modo <?= $theme === 'light' ? 'nocturno' : 'claro' ?></button></form>
            <details class="settings-menu">
                <summary class="btn">Mantenimiento</summary>
                <div class="settings-panel menu-panel">
                    <div class="menu-item">
                        <div class="menu-item-title">Personalización</div>
                        <div class="menu-subcontent">
                            <form method="post" class="form-grid compact">
                                <input type="hidden" name="action" value="set_wallpaper" />
                                <label>
                                    Fondo login
                                    <select name="wallpaper">
                                        <option value="">Sin imagen</option>
                                        <?php foreach ($wallpapers as $wall): ?>
                                            <option value="<?= h($wall) ?>" <?= $selectedWallpaper === $wall ? 'selected' : '' ?>><?= h(basename($wall)) ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </label>
                                <button type="submit" class="btn small">Aplicar</button>
                            </form>
                        </div>
                    </div>

                    <?php if ($user['role'] === ROLE_ADMIN): ?>
                        <details class="menu-item flyout-parent">
                            <summary class="menu-item-title">Usuario</summary>
                            <div class="flyout-menu">
                                <a class="menu-link menu-link-block" href="index.php?modal=create_user">Nuevo usuario</a>
                                <a class="menu-link menu-link-block" href="index.php?modal=reset_password">Recuperar contraseña</a>
                                <a class="menu-link menu-link-block" href="index.php?modal=edit_user">Modificar usuario</a>
                                <a class="menu-link menu-link-block" href="index.php?modal=list_users">Listar usuarios</a>
                            </div>
                        </details>
                    <?php endif; ?>
                </div>
            </details>
            <form method="post"><input type="hidden" name="action" value="logout"><button class="btn primary">Cerrar sesión</button></form>
        </div>
    </header>

    <?php if ($flash): ?>
        <div class="flash <?= h($flash['type']) ?>"><?= h($flash['message']) ?></div>
    <?php endif; ?>

    <nav class="view-nav card">
        <a class="btn small <?= $view === 'dashboard' ? 'primary' : '' ?>" href="index.php?view=dashboard">Dashboard</a>
        <a class="btn small <?= $view === 'ips' ? 'primary' : '' ?>" href="index.php?view=ips">Gestión de IPs</a>
    </nav>

    <?php if ($view === 'dashboard'): ?>
        <section class="card">
            <h2>Dashboard por segmento</h2>
            <form method="get" class="form-grid three dashboard-controls">
                <input type="hidden" name="view" value="dashboard">
                <label>Segmento
                    <select name="dashboard_segment">
                        <?php foreach ($segmentStats as $seg): ?>
                            <option value="<?= h($seg['segment']) ?>" <?= $dashboardData['segment'] === $seg['segment'] ? 'selected' : '' ?>><?= h($seg['segment']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </label>
                <div class="form-end"><button type="submit" class="btn small">Ver</button></div>
                <div class="form-end">
                    <?php if ($dashboardSegmentOctet !== ''): ?>
                        <a class="btn small" href="index.php?view=ips&amp;segment=<?= urlencode($dashboardSegmentOctet) ?>">Ver IPs de este segmento</a>
                    <?php else: ?>
                        <span class="btn small" aria-disabled="true">Ver IPs de este segmento</span>
                    <?php endif; ?>
                </div>
            </form>

            <?php if (!$segmentStats): ?>
                <div class="muted">No hay datos para mostrar dashboard.</div>
            <?php else: ?>
                <div class="dashboard-cards">
                    <?php foreach ($segmentStats as $seg): ?>
                        <?php $usedPct = min(100, max(0, (int) round(($seg['used'] / 254) * 100))); ?>
                        <a class="segment-card" href="index.php?view=dashboard&amp;dashboard_segment=<?= urlencode($seg['segment']) ?>">
                            <strong><?= h($seg['segment']) ?></strong>
                            <div>Usadas: <?= h((string) $seg['used']) ?></div>
                            <div>Libres: <?= h((string) $seg['free']) ?></div>
                            <div class="muted">Disponibilidad: <?= h((string) (100 - $usedPct)) ?>%</div>
                        </a>
                    <?php endforeach; ?>
                </div>

                <div class="dashboard-grid">
                    <div class="chart-wrap">
                        <div class="pie-chart" style="--used: <?= $dashboardUsedPct ?>;"></div>
                        <div>
                            <strong><?= h($dashboardData['segment']) ?></strong>
                            <div class="muted">Usadas: <?= h((string) $dashboardData['used']) ?> · Libres: <?= h((string) $dashboardData['free']) ?></div>
                            <div class="muted">Capacidad total por segmento: 254 IPs</div>
                        </div>
                    </div>
                    <div class="table-wrap">
                        <table>
                            <thead><tr><th>Segmento</th><th>IPs usadas</th><th>IPs libres</th><th>Disponibilidad</th></tr></thead>
                            <tbody>
                            <?php foreach ($segmentStats as $seg): ?>
                                <?php $usedPct = min(100, max(0, (int) round(($seg['used'] / 254) * 100))); ?>
                                <tr>
                                    <td><?= h($seg['segment']) ?></td>
                                    <td><?= h((string) $seg['used']) ?></td>
                                    <td><?= h((string) $seg['free']) ?></td>
                                    <td><?= h((string) (100 - $usedPct)) ?>%</td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            <?php endif; ?>
        </section>
    <?php endif; ?>

    <?php if ($view === 'ips'): ?>
        <?php if ($user['role'] === ROLE_ADMIN): ?>
        <details class="card collapsible-card" open>
            <summary><h2>Registrar IP</h2></summary>
            <form method="post" class="form-grid three">
                <input type="hidden" name="action" value="add_ip" />
                <input type="hidden" name="view" value="ips" />
                <label>IP<input type="text" name="ip_address" required></label>
                <label>Alias<input type="text" name="alias"></label>
                <label>Ubicación<input type="text" name="location"></label>
                <div class="form-end"><button type="submit" class="btn primary small">Registrar</button></div>
            </form>
        </details>
        <?php endif; ?>

        <details class="card collapsible-card" open>
            <summary><h2>Buscar y filtrar</h2></summary>
            <form method="get" class="form-grid four">
                <input type="hidden" name="view" value="ips" />
                <label>Segmento (/24 o solo rango)
                    <input type="text" name="segment" value="<?= h($segmentFilterInput) ?>" placeholder="Ej: 56 o 192.168.56.0/24">
                </label>
                <label>Número de IP
                    <input type="text" name="ip_filter" value="<?= h($ipFilterInput) ?>" placeholder="Ej: 192.168.56">
                </label>
                <label>Nombre equipo
                    <input type="text" name="name_filter" value="<?= h($nameFilterInput) ?>" placeholder="Hostname o alias">
                </label>
                <label>Ubicación
                    <input type="text" name="location_filter" value="<?= h($locationFilterInput) ?>" placeholder="Ej: Oficina 2">
                </label>
                <div class="form-end">
                    <button type="submit" class="btn small">Aplicar</button>
                    <a class="btn ghost small" href="index.php?view=ips">Limpiar</a>
                </div>
            </form>
        </details>

        <section class="card">
            <div class="card-title-row">
                <h2>IPs registradas</h2>
                <form method="post"><input type="hidden" name="action" value="ping_all" /><button class="btn primary small">Ejecutar ping manual</button></form>
            </div>
            <div class="table-wrap">
                <table>
                    <thead>
                    <tr>
                        <th>IP</th>
                        <th>Ubicación</th>
                        <th>Detalles</th>
                        <th>Estado</th>
                        <th>Acciones</th>
                    </tr>
                    </thead>
                    <tbody>
                    <?php if (!$rows): ?>
                        <tr><td colspan="5">No hay IPs registradas.</td></tr>
                    <?php else: ?>
                        <?php foreach ($rows as $row): ?>
                            <tr>
                                <td>
                                    <strong><?= h($row['ip_address']) ?></strong>
                                    <div class="muted"><?= h($row['host_name'] ?: '-') ?></div>
                                </td>
                                <td><?= h($row['location'] ?: '-') ?></td>
                                <td>
                                    Alias: <?= h($row['alias'] ?: '-') ?><br>
                                    Nombre: <?= h($row['host_name'] ?: '-') ?><br>
                                    Tipo: <?= h($row['host_type'] ?: '-') ?><br>
                                    Ubicación: <?= h($row['location'] ?: '-') ?><br>
                                    Notas: <?= h($row['notes'] ?: '-') ?><br>
                                    Segmento: <?= h($row['segment']) ?><br>
                                    Registrado por: <?= h($row['created_by'] ?: '-') ?>
                                </td>
                                <td>
                                    <?= h($row['last_status'] ?: 'SIN DATOS') ?>
                                    <div class="muted"><?= h($row['last_ping_at'] ? format_display_datetime($row['last_ping_at']) : 'Nunca') ?></div>
                                </td>
                                <td class="actions-col">
                                    <a class="btn small" href="index.php?view=ips&amp;action=detail&amp;ip=<?= urlencode($row['ip_address']) ?>">Detalles</a>
                                    <form method="post">
                                        <input type="hidden" name="action" value="ping_now">
                                        <input type="hidden" name="ip_address" value="<?= h($row['ip_address']) ?>">
                                        <button class="btn small">Ping</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </section>

        <?php if ($detail): ?>
            <div class="modal-backdrop">
            <section class="card modal-card">
                <h2>Detalle de IP - <?= h($detail['ip_address']) ?></h2>
                <a class="btn small ghost" href="index.php?view=ips">Cerrar</a>
                <form method="post" class="form-grid two">
                    <input type="hidden" name="action" value="save_ip" />
                    <input type="hidden" name="ip_address" value="<?= h($detail['ip_address']) ?>" />
                    <label>Alias<input type="text" name="alias" value="<?= h($detail['alias']) ?>"></label>
                    <label>Nombre<input type="text" name="host_name" value="<?= h($detail['host_name']) ?>"></label>
                    <label>Tipo
                        <select name="host_type">
                            <option value="">-</option>
                            <?php foreach (HOST_TYPES as $type): ?>
                                <option value="<?= h($type) ?>" <?= ($detail['host_type'] === $type) ? 'selected' : '' ?>><?= h($type) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </label>
                    <label>Ubicación<input type="text" name="location" value="<?= h($detail['location']) ?>"></label>
                    <label class="full">Notas<textarea name="notes" rows="3"><?= h($detail['notes']) ?></textarea></label>
                    <div class="form-end full"><button class="btn primary small" type="submit">Guardar cambios</button></div>
                </form>

                <h3>Resumen</h3>
                <table>
                    <tr><th>IP</th><td><?= h($detail['ip_address']) ?></td></tr>
                    <tr><th>Hostname</th><td><?= h($detail['host_name'] ?: '-') ?></td></tr>
                    <tr><th>Alias</th><td><?= h($detail['alias'] ?: '-') ?></td></tr>
                    <tr><th>Tipo</th><td><?= h($detail['host_type'] ?: '-') ?></td></tr>
                    <tr><th>Ubicación</th><td><?= h($detail['location'] ?: '-') ?></td></tr>
                    <tr><th>Notas</th><td><?= h($detail['notes'] ?: '-') ?></td></tr>
                    <tr><th>Último estado</th><td><?= h($detail['last_status'] ?: '-') ?></td></tr>
                    <tr><th>Último ping</th><td><?= h($detail['last_ping_at'] ? format_display_datetime($detail['last_ping_at']) : '-') ?></td></tr>
                    <tr><th>Registrado por</th><td><?= h($detail['created_by'] ?: '-') ?></td></tr>
                </table>
            </section>

            <section class="card modal-card">
                <h2>Historial de ping (últimos 7 días)</h2>
                <table>
                    <thead><tr><th>Fecha</th><th>Estado</th><th>Hostname</th></tr></thead>
                    <tbody>
                    <?php if (!$history): ?>
                        <tr><td colspan="3">No hay registros aún.</td></tr>
                    <?php else: ?>
                        <?php foreach ($history as $log): ?>
                            <tr>
                                <td><?= h(format_display_datetime($log['pinged_at'])) ?></td>
                                <td><?= h($log['status']) ?></td>
                                <td><?= h($log['hostname']) ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                    </tbody>
                </table>
            </section>
            </div>
        <?php endif; ?>
    <?php endif; ?>

    <?php if ($showCreateUserModal): ?>
        <div class="modal-backdrop">
            <section class="card modal-card create-user-modal">
                <h2>Crear usuario</h2>
                <a class="btn small ghost" href="index.php">Cerrar</a>
                <form method="post" class="form-grid two">
                    <input type="hidden" name="action" value="add_user" />
                    <label>Usuario<input type="text" name="username" required></label>
                    <label>Contraseña<input type="password" name="password" required></label>
                    <label>Nombre<input type="text" name="first_name"></label>
                    <label>Apellido<input type="text" name="last_name"></label>
                    <label>Rol
                        <select name="role">
                            <option value="<?= ROLE_OPERATOR ?>">Operador</option>
                            <option value="<?= ROLE_ADMIN ?>">Admin</option>
                        </select>
                    </label>
                    <div class="form-end"><button type="submit" class="btn primary small">Guardar usuario</button></div>
                </form>
            </section>
        </div>
    <?php endif; ?>

    <?php if ($showResetPasswordModal): ?>
        <div class="modal-backdrop">
            <section class="card modal-card create-user-modal">
                <h2>Recuperar contraseña</h2>
                <a class="btn small ghost" href="index.php">Cerrar</a>
                <form method="post" class="form-grid two">
                    <input type="hidden" name="action" value="reset_user_password" />
                    <label>Usuario
                        <select name="username" required>
                            <option value="">Seleccione...</option>
                            <?php foreach ($usersList as $usr): ?>
                                <option value="<?= h($usr['username']) ?>"><?= h($usr['username']) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </label>
                    <label>Nueva contraseña<input type="password" name="new_password" required></label>
                    <div class="form-end"><button type="submit" class="btn primary small">Actualizar contraseña</button></div>
                </form>
            </section>
        </div>
    <?php endif; ?>

    <?php if ($showEditUserModal): ?>
        <div class="modal-backdrop">
            <section class="card modal-card create-user-modal">
                <h2>Modificar usuario</h2>
                <a class="btn small ghost" href="index.php">Cerrar</a>
                <form method="post" class="form-grid two">
                    <input type="hidden" name="action" value="update_user" />
                    <label>Usuario
                        <select name="username" required>
                            <option value="">Seleccione...</option>
                            <?php foreach ($usersList as $usr): ?>
                                <option value="<?= h($usr['username']) ?>"><?= h($usr['username']) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </label>
                    <label>Rol
                        <select name="role">
                            <option value="<?= ROLE_OPERATOR ?>">Operador</option>
                            <option value="<?= ROLE_ADMIN ?>">Admin</option>
                        </select>
                    </label>
                    <label>Nombre<input type="text" name="first_name"></label>
                    <label>Apellido<input type="text" name="last_name"></label>
                    <label>Nueva contraseña (opcional)<input type="password" name="new_password"></label>
                    <div class="form-end"><button type="submit" class="btn primary small">Guardar cambios</button></div>
                </form>
            </section>
        </div>
    <?php endif; ?>

    <?php if ($showListUsersModal): ?>
        <div class="modal-backdrop">
            <section class="card modal-card create-user-modal">
                <h2>Usuarios actuales</h2>
                <a class="btn small ghost" href="index.php">Cerrar</a>
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Usuario</th><th>Nombre</th><th>Rol</th></tr></thead>
                        <tbody>
                        <?php if (!$usersList): ?>
                            <tr><td colspan="3">No hay usuarios.</td></tr>
                        <?php else: ?>
                            <?php foreach ($usersList as $usr): ?>
                                <tr>
                                    <td><?= h($usr['username']) ?></td>
                                    <td><?= h(trim(($usr['first_name'] ?? '') . ' ' . ($usr['last_name'] ?? '')) ?: '-') ?></td>
                                    <td><?= h($usr['role']) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </section>
        </div>
    <?php endif; ?>
</main>
</body>
</html>
