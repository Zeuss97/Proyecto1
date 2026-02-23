<?php

declare(strict_types=1);

const DB_DIR = __DIR__ . '/data';
const DB_PATH = DB_DIR . '/ips.db';
const ROLE_ADMIN = 'admin';
const ROLE_OPERATOR = 'operator';
const HOST_TYPES = ['NOTEBOOK', 'DESKTOP', 'SERVER', 'IMPRESORA', 'ROUTER', 'OTRO'];
const DISPLAY_TZ = '-03:00';
const AUTO_SCAN_TARGET_HOUR = 13;
const AUTO_SCAN_LAST_RUN_KEY = 'auto_scan_last_run_at';
const AUTO_SCAN_SEGMENT_KEY = 'auto_scan_segment';
const SCAN_POOL_SIZE_KEY = 'scan_pool_size';
const SCAN_DEFAULT_TIMEOUT_MS_KEY = 'scan_default_timeout_ms';
const SCAN_SEGMENT_TIMEOUT_MAX_MS_KEY = 'scan_segment_timeout_max_ms';
const SCAN_POOL_SIZE_DEFAULT = 100;
const SCAN_TIMEOUT_MIN_MS = 300;
const SCAN_TIMEOUT_MAX_MS = 2000;
const DEFAULT_SCAN_TIMEOUT_MS = 2000;
const SEGMENT_SCAN_TIMEOUT_MIN_MS = 180;
const SEGMENT_SCAN_TIMEOUT_MAX_MS_DEFAULT = 2000;
const SEGMENT_SCAN_MAX_DURATION_MS = 90000;
const TCP_FALLBACK_PORT = 80;

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

function iso_after_seconds(int $seconds): string
{
    $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
    if ($seconds >= 0) {
        return $now->add(new DateInterval('PT' . $seconds . 'S'))->format(DateTimeInterface::ATOM);
    }
    return $now->sub(new DateInterval('PT' . abs($seconds) . 'S'))->format(DateTimeInterface::ATOM);
}

function next_auto_ping_iso(): string
{
    $jitter = random_int(-300, 300);
    return iso_after_seconds(1800 + $jitter);
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
    $pdo->exec('CREATE TABLE IF NOT EXISTS app_settings (
        setting_key TEXT PRIMARY KEY,
        setting_value TEXT
    )');

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
        last_seen_online_at TEXT,
        next_auto_ping_at TEXT,
        last_status TEXT,
        last_output TEXT,
        last_uptime TEXT,
        created_at TEXT NOT NULL,
        created_by TEXT
    )');

    $columns = $pdo->query('PRAGMA table_info(ip_registry)')->fetchAll();
    $columnNames = array_column($columns, 'name');
    if (!in_array('created_by', $columnNames, true)) {
        $pdo->exec('ALTER TABLE ip_registry ADD COLUMN created_by TEXT');
    }
    if (!in_array('last_uptime', $columnNames, true)) {
        $pdo->exec('ALTER TABLE ip_registry ADD COLUMN last_uptime TEXT');
    }
    if (!in_array('last_seen_online_at', $columnNames, true)) {
        $pdo->exec('ALTER TABLE ip_registry ADD COLUMN last_seen_online_at TEXT');
    }
    if (!in_array('next_auto_ping_at', $columnNames, true)) {
        $pdo->exec('ALTER TABLE ip_registry ADD COLUMN next_auto_ping_at TEXT');
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

function get_app_setting(string $key, string $default = ''): string
{
    $stmt = db()->prepare('SELECT setting_value FROM app_settings WHERE setting_key = :setting_key');
    $stmt->execute(['setting_key' => $key]);
    $value = $stmt->fetchColumn();
    return $value === false ? $default : (string) $value;
}

function set_app_setting(string $key, string $value): void
{
    $stmt = db()->prepare('INSERT INTO app_settings (setting_key, setting_value)
        VALUES (:setting_key, :setting_value)
        ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value');
    $stmt->execute([
        'setting_key' => $key,
        'setting_value' => $value,
    ]);
}

function get_app_setting_int(string $key, int $default, int $min, int $max): int
{
    $raw = trim(get_app_setting($key, (string) $default));
    if ($raw === '' || !preg_match('/^-?\d+$/', $raw)) {
        return clamp_int($default, $min, $max);
    }

    return clamp_int((int) $raw, $min, $max);
}

function get_scan_pool_size(): int
{
    return get_app_setting_int(SCAN_POOL_SIZE_KEY, SCAN_POOL_SIZE_DEFAULT, 1, 256);
}

function get_scan_default_timeout_ms(): int
{
    return get_app_setting_int(SCAN_DEFAULT_TIMEOUT_MS_KEY, DEFAULT_SCAN_TIMEOUT_MS, SCAN_TIMEOUT_MIN_MS, SCAN_TIMEOUT_MAX_MS);
}

function get_scan_segment_timeout_max_ms(): int
{
    return get_app_setting_int(SCAN_SEGMENT_TIMEOUT_MAX_MS_KEY, SEGMENT_SCAN_TIMEOUT_MAX_MS_DEFAULT, SEGMENT_SCAN_TIMEOUT_MIN_MS, SCAN_TIMEOUT_MAX_MS);
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

function json_response(array $payload, int $statusCode = 200): never
{
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    exit;
}

function is_json_request(): bool
{
    $accept = strtolower((string) ($_SERVER['HTTP_ACCEPT'] ?? ''));
    $requestedWith = strtolower((string) ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? ''));
    return str_contains($accept, 'application/json') || $requestedWith === 'xmlhttprequest';
}

function safe_redirect_target(?string $target, string $default = 'index.php'): string
{
    $raw = trim((string) $target);
    if ($raw === '' || str_starts_with($raw, 'http://') || str_starts_with($raw, 'https://') || str_starts_with($raw, '//')) {
        return $default;
    }
    if (!str_starts_with($raw, 'index.php')) {
        return $default;
    }
    return $raw;
}

function h(?string $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

function validate_ip(string $ip): bool
{
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

function ip_sort_value(string $ip): int
{
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        $long = ip2long($ip);
        if ($long !== false) {
            return (int) sprintf('%u', $long);
        }
    }
    return PHP_INT_MAX;
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

function resolve_scan_segment_prefix(string $input): ?string
{
    $raw = trim($input);
    if ($raw === '') {
        return null;
    }

    if (preg_match('/^(\d{1,3})$/', $raw, $m) || preg_match('/^(\d{1,3})\/24$/', $raw, $m)) {
        $octet = (int) $m[1];
        if ($octet >= 0 && $octet <= 255) {
            return '192.168.' . $octet;
        }
    }

    if (preg_match('/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/', $raw, $m)
        || preg_match('/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.0\/24$/', $raw, $m)) {
        foreach ([1, 2, 3] as $idx) {
            $value = (int) $m[$idx];
            if ($value < 0 || $value > 255) {
                return null;
            }
        }
        return sprintf('%d.%d.%d', $m[1], $m[2], $m[3]);
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

function reverse_dns_lookup(string $ip): ?string
{
    static $cache = [];
    if (array_key_exists($ip, $cache)) {
        return $cache[$ip];
    }

    $resolved = @gethostbyaddr($ip);
    if ($resolved !== false && $resolved !== $ip) {
        $cache[$ip] = $resolved;
        return $resolved;
    }

    $cache[$ip] = null;
    return null;
}

function probe_uptime(string $ip): ?string
{
    $snmpPath = trim((string) @shell_exec('command -v snmpget 2>/dev/null'));
    if ($snmpPath === '') {
        return null;
    }

    $cmd = sprintf('%s -v2c -c public -t 1 -r 0 %s 1.3.6.1.2.1.1.3.0 2>/dev/null', escapeshellcmd($snmpPath), escapeshellarg($ip));
    $raw = trim((string) @shell_exec($cmd));
    if ($raw === '') {
        return null;
    }

    if (preg_match('/\((\d+)\)/', $raw, $m)) {
        $ticks = (int) $m[1];
        $seconds = (int) floor($ticks / 100);
        $days = intdiv($seconds, 86400);
        $hours = intdiv($seconds % 86400, 3600);
        $minutes = intdiv($seconds % 3600, 60);
        $secs = $seconds % 60;
        if ($days > 0) {
            return sprintf('%dd %02d:%02d:%02d', $days, $hours, $minutes, $secs);
        }
        return sprintf('%02d:%02d:%02d', $hours, $minutes, $secs);
    }

    return null;
}

function clamp_int(int $value, int $min, int $max): int
{
    return max($min, min($max, $value));
}

function parse_rtt_ms_from_output(string $output): ?float
{
    if (preg_match('/time[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms/i', $output, $m)) {
        return (float) $m[1];
    }
    return null;
}

function build_icmp_ping_command(string $ip, int $timeoutMs): string
{
    $isWindows = strtoupper(substr(PHP_OS_FAMILY, 0, 3)) === 'WIN';
    if ($isWindows) {
        return sprintf('ping -n 1 -w %d %s', $timeoutMs, escapeshellarg($ip));
    }

    $timeoutSeconds = max(1, (int) ceil($timeoutMs / 1000));
    $deadlineSeconds = $timeoutSeconds + 1;
    $pingCmd = sprintf('ping -n -c 1 -W %d -w %d %s', $timeoutSeconds, $deadlineSeconds, escapeshellarg($ip));
    $timeoutBin = trim((string) @shell_exec('command -v timeout 2>/dev/null'));

    if ($timeoutBin !== '') {
        return sprintf('%s %d %s', escapeshellcmd($timeoutBin), $deadlineSeconds + 1, $pingCmd);
    }

    return $pingCmd;
}

function run_icmp_ping(string $ip, int $timeoutMs): array
{
    $command = build_icmp_ping_command($ip, $timeoutMs);
    $outputLines = [];
    $exitCode = 1;
    @exec($command . ' 2>&1', $outputLines, $exitCode);

    $output = trim(implode(PHP_EOL, $outputLines));
    return [
        'status' => $exitCode === 0 ? 'OK' : 'ERROR',
        'output' => $output,
        'latency_ms' => parse_rtt_ms_from_output($output),
        'method' => 'ICMP',
    ];
}

function probe_tcp_connect(string $ip, int $port, int $timeoutMs): bool
{
    $timeoutSeconds = max(0.2, $timeoutMs / 1000);
    $errno = 0;
    $errstr = '';
    $socket = @fsockopen($ip, $port, $errno, $errstr, $timeoutSeconds);
    if ($socket === false) {
        return false;
    }
    fclose($socket);
    return true;
}

function finalize_ping_result(string $ip, array $result): array
{
    $hostname = null;
    if (($result['status'] ?? 'ERROR') === 'OK') {
        $hostname = reverse_dns_lookup($ip);
    }

    $result['hostname'] = $hostname;
    return $result;
}

function apply_tcp_fallback(string $ip, array $icmpResult, int $timeoutMs): array
{
    if (probe_tcp_connect($ip, TCP_FALLBACK_PORT, $timeoutMs)) {
        return finalize_ping_result($ip, [
            'status' => 'OK',
            'output' => trim(($icmpResult['output'] ?? '') . PHP_EOL . sprintf('TCP fallback OK (%s:%d)', $ip, TCP_FALLBACK_PORT)),
            'latency_ms' => null,
            'method' => 'TCP',
        ]);
    }

    return finalize_ping_result($ip, $icmpResult);
}

function ping_ip(string $ip, int $timeoutMs = DEFAULT_SCAN_TIMEOUT_MS): array
{
    $timeoutMs = clamp_int($timeoutMs, SCAN_TIMEOUT_MIN_MS, SCAN_TIMEOUT_MAX_MS);
    $icmpResult = run_icmp_ping($ip, $timeoutMs);

    if ($icmpResult['status'] === 'OK') {
        return finalize_ping_result($ip, $icmpResult);
    }

    return apply_tcp_fallback($ip, $icmpResult, $timeoutMs);
}

function start_async_icmp_ping(string $ip, int $timeoutMs)
{
    $command = build_icmp_ping_command($ip, $timeoutMs);
    $descriptorSpec = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];

    $process = @proc_open($command, $descriptorSpec, $pipes);
    if (!is_resource($process)) {
        return null;
    }

    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);

    return [
        'process' => $process,
        'stdout' => $pipes[1],
        'stderr' => $pipes[2],
        'buffer' => '',
        'ip' => $ip,
    ];
}

function finish_async_icmp_ping(array $task): array
{
    $stdout = stream_get_contents($task['stdout']) ?: '';
    $stderr = stream_get_contents($task['stderr']) ?: '';
    fclose($task['stdout']);
    fclose($task['stderr']);

    $exitCode = proc_close($task['process']);
    $output = trim($task['buffer'] . $stdout . $stderr);

    return [
        'status' => $exitCode === 0 ? 'OK' : 'ERROR',
        'output' => $output,
        'latency_ms' => parse_rtt_ms_from_output($output),
        'method' => 'ICMP',
    ];
}

function scan_ips_parallel(array $ips, int $poolSize): array
{
    $poolSize = clamp_int($poolSize, 1, SCAN_POOL_SIZE_DEFAULT);
    $queue = array_values($ips);
    $running = [];
    $results = [];
    $rttSamples = [];
    $startedAt = microtime(true);

    while ($queue !== [] || $running !== []) {
        $elapsedMs = (int) round((microtime(true) - $startedAt) * 1000);
        if ($elapsedMs >= SEGMENT_SCAN_MAX_DURATION_MS) {
            foreach ($running as $ip => $task) {
                @proc_terminate($task['process']);
                fclose($task['stdout']);
                fclose($task['stderr']);
                @proc_close($task['process']);
                $results[$ip] = [
                    'status' => 'ERROR',
                    'output' => 'Escaneo cancelado por límite de tiempo del segmento',
                    'latency_ms' => null,
                    'method' => 'ICMP',
                    'hostname' => null,
                ];
            }
            foreach ($queue as $ip) {
                $results[$ip] = [
                    'status' => 'ERROR',
                    'output' => 'Escaneo cancelado por límite de tiempo del segmento',
                    'latency_ms' => null,
                    'method' => 'ICMP',
                    'hostname' => null,
                ];
            }
            break;
        }

        $sampleAvg = $rttSamples === []
            ? get_scan_default_timeout_ms() / 3
            : array_sum($rttSamples) / count($rttSamples);
        $dynamicTimeoutMs = clamp_int((int) round($sampleAvg * 3), SEGMENT_SCAN_TIMEOUT_MIN_MS, get_scan_segment_timeout_max_ms());

        while ($queue !== [] && count($running) < $poolSize) {
            $ip = array_shift($queue);
            $task = start_async_icmp_ping($ip, $dynamicTimeoutMs);
            if ($task === null) {
                $results[$ip] = ping_ip($ip, $dynamicTimeoutMs);
                continue;
            }
            $running[$ip] = $task;
        }

        foreach ($running as $ip => &$task) {
            $task['buffer'] .= stream_get_contents($task['stdout']) ?: '';
            $task['buffer'] .= stream_get_contents($task['stderr']) ?: '';
            $status = proc_get_status($task['process']);
            if ($status['running']) {
                continue;
            }

            $icmpResult = finish_async_icmp_ping($task);
            if ($icmpResult['status'] === 'OK') {
                if ($icmpResult['latency_ms'] !== null) {
                    $rttSamples[] = $icmpResult['latency_ms'];
                    if (count($rttSamples) > 32) {
                        array_shift($rttSamples);
                    }
                }
                $results[$ip] = finalize_ping_result($ip, $icmpResult);
            } else {
                $results[$ip] = apply_tcp_fallback($ip, $icmpResult, $dynamicTimeoutMs);
            }

            unset($running[$ip]);
        }
        unset($task);

        if ($running !== []) {
            usleep(5000);
        }
    }

    return $results;
}

function run_ping_for_ip(string $ip): void
{
    $result = ping_ip($ip, get_scan_default_timeout_ms());
    $uptime = probe_uptime($ip);
    $timestamp = now_iso();
    $lastSeenOnlineAt = $result['status'] === 'OK' ? $timestamp : null;

    $update = db()->prepare('UPDATE ip_registry
        SET last_ping_at = :last_ping_at, last_status = :last_status, last_output = :last_output,
            last_seen_online_at = COALESCE(:last_seen_online_at, last_seen_online_at),
            next_auto_ping_at = :next_auto_ping_at,
            last_uptime = COALESCE(:last_uptime, last_uptime),
            host_name = COALESCE(NULLIF(:host_name, ""), host_name)
        WHERE ip_address = :ip_address');
    $update->execute([
        'last_ping_at' => $timestamp,
        'last_status' => $result['status'],
        'last_output' => $result['output'],
        'last_seen_online_at' => $lastSeenOnlineAt,
        'next_auto_ping_at' => next_auto_ping_iso(),
        'last_uptime' => $uptime,
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

function upsert_scanned_ip(string $ip, array $result, string $createdBy): string
{
    $timestamp = now_iso();
    $uptime = probe_uptime($ip);
    $resolvedAlias = trim((string) ($result['hostname'] ?? ''));
    try {
        $insert = db()->prepare('INSERT INTO ip_registry (
            ip_address, alias, host_name, location, last_ping_at, last_seen_online_at, next_auto_ping_at, last_status, last_output, last_uptime, created_at, created_by
        ) VALUES (
            :ip_address, :alias, :host_name, :location, :last_ping_at, :last_seen_online_at, :next_auto_ping_at, :last_status, :last_output, :last_uptime, :created_at, :created_by
        )');
        $insert->execute([
            'ip_address' => $ip,
            'alias' => $resolvedAlias,
            'host_name' => $result['hostname'] ?? '',
            'location' => '',
            'last_ping_at' => $timestamp,
            'last_seen_online_at' => $timestamp,
            'next_auto_ping_at' => next_auto_ping_iso(),
            'last_status' => $result['status'],
            'last_output' => $result['output'],
            'last_uptime' => $uptime,
            'created_at' => $timestamp,
            'created_by' => $createdBy,
        ]);
        return 'inserted';
    } catch (PDOException) {
        $update = db()->prepare('UPDATE ip_registry SET
            last_ping_at = :last_ping_at,
            last_seen_online_at = :last_seen_online_at,
            next_auto_ping_at = :next_auto_ping_at,
            last_status = :last_status,
            last_output = :last_output,
            last_uptime = COALESCE(:last_uptime, last_uptime),
            alias = CASE
                WHEN alias IS NULL OR TRIM(alias) = "" OR UPPER(TRIM(alias)) = "LIBRE"
                    THEN COALESCE(NULLIF(:alias, ""), alias)
                ELSE alias
            END,
            host_name = COALESCE(NULLIF(:host_name, ""), host_name)
            WHERE ip_address = :ip_address');
        $update->execute([
            'last_ping_at' => $timestamp,
            'last_seen_online_at' => $timestamp,
            'next_auto_ping_at' => next_auto_ping_iso(),
            'last_status' => $result['status'],
            'last_output' => $result['output'],
            'last_uptime' => $uptime,
            'alias' => $resolvedAlias,
            'host_name' => $result['hostname'] ?? '',
            'ip_address' => $ip,
        ]);
        return 'updated';
    }
}

function count_ips_in_prefix(string $prefix): int
{
    $stmt = db()->prepare('SELECT COUNT(*) FROM ip_registry WHERE ip_address LIKE :prefix_like');
    $stmt->execute(['prefix_like' => $prefix . '.%']);
    return (int) $stmt->fetchColumn();
}

function insert_free_placeholder_ip(string $ip, string $createdBy): bool
{
    $timestamp = now_iso();
    try {
        $stmt = db()->prepare('INSERT INTO ip_registry (
            ip_address, alias, host_name, location, last_ping_at, last_status, last_output, created_at, created_by
        ) VALUES (
            :ip_address, :alias, :host_name, :location, :last_ping_at, :last_status, :last_output, :created_at, :created_by
        )');
        $stmt->execute([
            'ip_address' => $ip,
            'alias' => 'LIBRE',
            'host_name' => '',
            'location' => '',
            'last_ping_at' => $timestamp,
            'last_status' => 'ERROR',
            'last_output' => 'No responde (placeholder primer escaneo)',
            'created_at' => $timestamp,
            'created_by' => $createdBy,
        ]);
        return true;
    } catch (PDOException) {
        return false;
    }
}

function run_due_auto_pings(int $limit = 1): void
{
    $stmt = db()->prepare('SELECT ip_address FROM ip_registry
        WHERE next_auto_ping_at IS NULL OR next_auto_ping_at <= :now
        ORDER BY COALESCE(next_auto_ping_at, "") ASC
        LIMIT :limit');
    $stmt->bindValue(':now', now_iso(), PDO::PARAM_STR);
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll();

    foreach ($rows as $row) {
        run_ping_for_ip($row['ip_address']);
    }
}

function resolve_auto_scan_prefix(): ?string
{
    $configured = trim(get_app_setting(AUTO_SCAN_SEGMENT_KEY, ''));
    if ($configured !== '') {
        return resolve_scan_segment_prefix($configured);
    }

    $rows = db()->query('SELECT ip_address FROM ip_registry')->fetchAll();
    $segments = [];
    foreach ($rows as $row) {
        $ip = (string) ($row['ip_address'] ?? '');
        if (!validate_ip($ip) || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            continue;
        }

        $parts = explode('.', $ip);
        if (count($parts) !== 4) {
            continue;
        }

        $prefix = $parts[0] . '.' . $parts[1] . '.' . $parts[2];
        if (!isset($segments[$prefix])) {
            $segments[$prefix] = 0;
        }
        $segments[$prefix]++;
    }

    if ($segments === []) {
        return null;
    }

    arsort($segments);
    return (string) array_key_first($segments);
}

function run_segment_scan(string $prefix, string $createdBy): array
{
    $foundOnline = 0;
    $inserted = 0;
    $updated = 0;
    $markedFree = 0;
    $existingInSegment = count_ips_in_prefix($prefix);
    $seedOfflineAsFree = $existingInSegment === 0;

    $ips = [];
    for ($host = 1; $host <= 254; $host++) {
        $ips[] = $prefix . '.' . $host;
    }

    $scanResults = scan_ips_parallel($ips, get_scan_pool_size());
    usort($ips, static fn(string $a, string $b): int => ip_sort_value($a) <=> ip_sort_value($b));

    foreach ($ips as $ip) {
        $result = $scanResults[$ip] ?? ['status' => 'ERROR', 'output' => 'Sin resultado de escaneo'];
        if ($result['status'] !== 'OK') {
            if ($seedOfflineAsFree && insert_free_placeholder_ip($ip, $createdBy)) {
                $markedFree++;
            }
            continue;
        }

        $foundOnline++;
        $state = upsert_scanned_ip($ip, $result, $createdBy);
        if ($state === 'inserted') {
            $inserted++;
            continue;
        }
        $updated++;
    }

    return [
        'found_online' => $foundOnline,
        'inserted' => $inserted,
        'updated' => $updated,
        'marked_free' => $markedFree,
        'seeded_full_segment' => $seedOfflineAsFree,
    ];
}

function run_daily_auto_scan_if_due(): void
{
    $tz = new DateTimeZone(DISPLAY_TZ);
    $nowLocal = (new DateTimeImmutable('now', new DateTimeZone('UTC')))->setTimezone($tz);
    if ((int) $nowLocal->format('G') < AUTO_SCAN_TARGET_HOUR) {
        return;
    }

    $lastRunRaw = trim(get_app_setting(AUTO_SCAN_LAST_RUN_KEY, ''));
    if ($lastRunRaw !== '') {
        try {
            $lastRunLocal = (new DateTimeImmutable($lastRunRaw))->setTimezone($tz);
            if ($lastRunLocal->format('Y-m-d') === $nowLocal->format('Y-m-d')) {
                return;
            }
        } catch (Exception) {
            // Si el valor guardado está corrupto, se re-ejecuta y se corrige abajo.
        }
    }

    $prefix = resolve_auto_scan_prefix();
    if ($prefix === null) {
        return;
    }

    run_segment_scan($prefix, 'system-auto-scan');
    set_app_setting(AUTO_SCAN_LAST_RUN_KEY, now_iso());
}

function run_background_maintenance(int $pingLimit = 1): void
{
    $lockPath = DB_DIR . '/maintenance.lock';
    $handle = fopen($lockPath, 'c+');
    if ($handle === false) {
        return;
    }

    if (!flock($handle, LOCK_EX | LOCK_NB)) {
        fclose($handle);
        return;
    }

    try {
        run_due_auto_pings($pingLimit);
        run_daily_auto_scan_if_due();
    } finally {
        flock($handle, LOCK_UN);
        fclose($handle);
    }
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

if (PHP_SAPI === 'cli') {
    $cliCommand = $argv[1] ?? '';
    if ($cliCommand === 'worker') {
        run_background_maintenance(10);
        echo "OK\n";
        exit(0);
    }
}

run_background_maintenance();

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
    $wallpaper = trim(get_app_setting('login_wallpaper', ''));
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
        set_app_setting('login_wallpaper', $choice);
    }
    redirect('index.php');
}

if ($action === 'toggle_theme') {
    $_SESSION['theme'] = (($_SESSION['theme'] ?? 'light') === 'light') ? 'dark' : 'light';
    $redirectTo = safe_redirect_target($_POST['redirect_to'] ?? null, 'index.php');
    redirect($redirectTo);
}

if ($action === 'save_scan_profile') {
    if ($user['role'] !== ROLE_ADMIN) {
        flash('Solo admin puede modificar el perfil de escaneo.', 'error');
        redirect('index.php');
    }

    $poolSize = clamp_int((int) ($_POST['scan_pool_size'] ?? SCAN_POOL_SIZE_DEFAULT), 1, 256);
    $defaultTimeout = clamp_int((int) ($_POST['scan_default_timeout_ms'] ?? DEFAULT_SCAN_TIMEOUT_MS), SCAN_TIMEOUT_MIN_MS, SCAN_TIMEOUT_MAX_MS);
    $segmentTimeoutMax = clamp_int((int) ($_POST['scan_segment_timeout_max_ms'] ?? SEGMENT_SCAN_TIMEOUT_MAX_MS_DEFAULT), SEGMENT_SCAN_TIMEOUT_MIN_MS, SCAN_TIMEOUT_MAX_MS);

    set_app_setting(SCAN_POOL_SIZE_KEY, (string) $poolSize);
    set_app_setting(SCAN_DEFAULT_TIMEOUT_MS_KEY, (string) $defaultTimeout);
    set_app_setting(SCAN_SEGMENT_TIMEOUT_MAX_MS_KEY, (string) $segmentTimeoutMax);

    flash('Perfil de escaneo actualizado.', 'success');
    redirect('index.php');
}

if ($action === 'add_ip') {
    if (!in_array($user['role'], [ROLE_ADMIN, ROLE_OPERATOR], true)) {
        flash('No tienes permisos para registrar IPs.', 'error');
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

if ($action === 'scan_segment') {
    if ($user['role'] !== ROLE_ADMIN) {
        flash('Solo admin puede escanear segmentos.', 'error');
        redirect('index.php?view=ips');
    }

    $segmentInput = trim((string) ($_POST['segment_scan'] ?? ''));
    $prefix = resolve_scan_segment_prefix($segmentInput);
    if ($prefix === null) {
        flash('Segmento inválido. Usa por ejemplo 56, 56/24 o 192.168.56.0/24.', 'error');
        redirect('index.php?view=ips');
    }

    $scanStats = run_segment_scan($prefix, $user['username']);

    $message = sprintf('Escaneo %s. Online: %d, nuevas: %d, actualizadas: %d.', $prefix . '.0/24', $scanStats['found_online'], $scanStats['inserted'], $scanStats['updated']);
    if ($scanStats['seeded_full_segment']) {
        $message .= sprintf(' Marcadas como LIBRE (sin respuesta): %d.', $scanStats['marked_free']);
    }
    flash($message, 'success');
    $segmentOctet = explode('.', $prefix)[2] ?? '';
    redirect('index.php?view=ips&segment=' . urlencode((string) $segmentOctet));
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
    $returnTo = safe_redirect_target((string) ($_POST['return_to'] ?? ''), 'index.php?view=ips');

    if (!validate_ip($ip)) {
        if (is_json_request()) {
            json_response([
                'ok' => false,
                'message' => 'IP inválida.',
            ], 422);
        }
        flash('IP inválida.', 'error');
        redirect($returnTo);
    }

    run_ping_for_ip($ip);

    $rowStmt = db()->prepare('SELECT ip_address, host_name, last_status, last_ping_at FROM ip_registry WHERE ip_address = :ip_address');
    $rowStmt->execute(['ip_address' => $ip]);
    $row = $rowStmt->fetch() ?: [];

    if (is_json_request()) {
        $status = strtoupper((string) ($row['last_status'] ?? 'SIN DATOS'));
        json_response([
            'ok' => true,
            'message' => 'Ping ejecutado para ' . $ip . '.',
            'ip' => $ip,
            'status' => $status,
            'status_class' => $status === 'OK' ? 'ok' : ($status === 'ERROR' ? 'error' : 'unknown'),
            'hostname' => (string) ($row['host_name'] ?? ''),
            'last_ping_at' => (string) ($row['last_ping_at'] ?? ''),
            'last_ping_at_display' => format_display_datetime((string) ($row['last_ping_at'] ?? '')),
        ]);
    }

    flash('Ping ejecutado para ' . $ip . '.', 'success');
    redirect($returnTo);
}

if ($action === 'ping_all') {
    $rows = db()->query('SELECT ip_address FROM ip_registry')->fetchAll();
    usort($rows, static fn(array $a, array $b): int => ip_sort_value($a['ip_address']) <=> ip_sort_value($b['ip_address']));
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
$statusFilterInput = strtolower(trim((string) ($_GET['status_filter'] ?? 'all')));
$allowedStatusFilters = ['all', 'ok', 'error'];
if (!in_array($statusFilterInput, $allowedStatusFilters, true)) {
    $statusFilterInput = 'all';
}

$perPageOptions = [10, 20, 30, 40, 50, 100, 150, 200, 250];
$perPageInput = (int) ($_GET['per_page'] ?? 50);
if (!in_array($perPageInput, $perPageOptions, true)) {
    $perPageInput = 50;
}
$pageInput = max(1, (int) ($_GET['page'] ?? 1));

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

$conditionsWithoutStatus = $conditions;

if ($statusFilterInput === 'ok') {
    $conditions[] = 'UPPER(COALESCE(last_status, "")) = "OK"';
} elseif ($statusFilterInput === 'error') {
    $conditions[] = 'UPPER(COALESCE(last_status, "")) = "ERROR"';
}

if ($conditions) {
    $sql .= ' WHERE ' . implode(' AND ', $conditions);
}
$sql .= ' ORDER BY ip_address';
$stmt = db()->prepare($sql);
$stmt->execute($params);
$rows = $stmt->fetchAll();
usort($rows, static fn(array $a, array $b): int => ip_sort_value($a['ip_address']) <=> ip_sort_value($b['ip_address']));

$totalRows = count($rows);
$totalPages = max(1, (int) ceil($totalRows / $perPageInput));
$currentPage = min($pageInput, $totalPages);
$offset = ($currentPage - 1) * $perPageInput;
$rows = array_slice($rows, $offset, $perPageInput);

$baseQueryParams = [
    'view' => 'ips',
    'segment' => $segmentFilterInput,
    'ip_filter' => $ipFilterInput,
    'name_filter' => $nameFilterInput,
    'location_filter' => $locationFilterInput,
    'status_filter' => $statusFilterInput,
    'per_page' => (string) $perPageInput,
];
$statusCountsSql = 'SELECT
    SUM(CASE WHEN UPPER(COALESCE(last_status, "")) = "OK" THEN 1 ELSE 0 END) AS ok_count,
    SUM(CASE WHEN UPPER(COALESCE(last_status, "")) = "ERROR" THEN 1 ELSE 0 END) AS error_count
    FROM ip_registry';
if ($conditionsWithoutStatus !== []) {
    $statusCountsSql .= ' WHERE ' . implode(' AND ', $conditionsWithoutStatus);
}
$statusCountsStmt = db()->prepare($statusCountsSql);
$statusCountsStmt->execute($params);
$statusCounts = $statusCountsStmt->fetch() ?: ['ok_count' => 0, 'error_count' => 0];

foreach ($rows as &$row) {
    $row['segment'] = compute_segment($row['ip_address']);
}
unset($row);

$allIpRows = db()->query('SELECT ip_address, alias, host_name FROM ip_registry ORDER BY ip_address')->fetchAll();
$segmentStatsMap = [];
foreach ($allIpRows as $ipRow) {
    $segment = compute_segment($ipRow['ip_address']);
    if (!isset($segmentStatsMap[$segment])) {
        $segmentStatsMap[$segment] = ['segment' => $segment, 'used' => 0, 'free' => 254];
    }

    $alias = strtoupper(trim((string) ($ipRow['alias'] ?? '')));
    $hostname = trim((string) ($ipRow['host_name'] ?? ''));
    $isFreePlaceholder = $alias === 'LIBRE' && $hostname === '';
    if (!$isFreePlaceholder) {
        $segmentStatsMap[$segment]['used']++;
    }
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
$selectedWallpaper = get_app_setting('login_wallpaper', '');
$scanProfile = [
    'pool_size' => get_scan_pool_size(),
    'default_timeout_ms' => get_scan_default_timeout_ms(),
    'segment_timeout_max_ms' => get_scan_segment_timeout_max_ms(),
];
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
$currentUrl = 'index.php' . ($_GET ? ('?' . http_build_query($_GET)) : '');
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
            <form method="post">
                <input type="hidden" name="action" value="toggle_theme">
                <input type="hidden" name="redirect_to" value="<?= h($currentUrl) ?>">
                <button class="btn">Modo <?= $theme === 'light' ? 'nocturno' : 'claro' ?></button>
            </form>
            <?php if ($user['role'] === ROLE_ADMIN): ?>
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

                        <details class="menu-item flyout-parent">
                            <summary class="menu-item-title">Escaneo</summary>
                            <div class="flyout-menu">
                                <form method="post" class="form-grid compact">
                                    <input type="hidden" name="action" value="save_scan_profile" />
                                    <label>Hilos máximos
                                        <input type="number" min="1" max="256" name="scan_pool_size" value="<?= h((string) $scanProfile['pool_size']) ?>">
                                    </label>
                                    <label>Timeout ping por defecto (ms)
                                        <input type="number" min="<?= h((string) SCAN_TIMEOUT_MIN_MS) ?>" max="<?= h((string) SCAN_TIMEOUT_MAX_MS) ?>" name="scan_default_timeout_ms" value="<?= h((string) $scanProfile['default_timeout_ms']) ?>">
                                    </label>
                                    <label>Timeout máximo escaneo segmento (ms)
                                        <input type="number" min="<?= h((string) SEGMENT_SCAN_TIMEOUT_MIN_MS) ?>" max="<?= h((string) SCAN_TIMEOUT_MAX_MS) ?>" name="scan_segment_timeout_max_ms" value="<?= h((string) $scanProfile['segment_timeout_max_ms']) ?>">
                                    </label>
                                    <button type="submit" class="btn small">Guardar</button>
                                </form>
                            </div>
                        </details>

                        <details class="menu-item flyout-parent">
                            <summary class="menu-item-title">Usuario</summary>
                            <div class="flyout-menu">
                                <a class="menu-link menu-link-block" href="index.php?modal=create_user">Nuevo usuario</a>
                                <a class="menu-link menu-link-block" href="index.php?modal=reset_password">Recuperar contraseña</a>
                                <a class="menu-link menu-link-block" href="index.php?modal=edit_user">Modificar usuario</a>
                                <a class="menu-link menu-link-block" href="index.php?modal=list_users">Listar usuarios</a>
                            </div>
                        </details>
                    </div>
                </details>
            <?php endif; ?>
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
        <?php if (in_array($user['role'], [ROLE_ADMIN, ROLE_OPERATOR], true)): ?>
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

        <?php if ($user['role'] === ROLE_ADMIN): ?>
        <details class="card collapsible-card" open>
            <summary><h2>Escanear segmento (/24)</h2></summary>
            <form method="post" class="form-grid three">
                <input type="hidden" name="action" value="scan_segment" />
                <label>Segmento
                    <input type="text" name="segment_scan" required placeholder="Ej: 56, 56/24 o 192.168.56.0/24">
                </label>
                <div class="form-end"><button type="submit" class="btn small">Escanear e importar IPs online</button></div>
            </form>
            <div class="muted">Escanea hosts 1..254 del segmento y registra/actualiza las IPs que respondan ping.</div>
        </details>
        <?php endif; ?>
        <?php endif; ?>

        <details class="card collapsible-card" open>
            <summary><h2>Buscar y filtrar</h2></summary>
            <form method="get" class="form-grid four">
                <input type="hidden" name="view" value="ips" />
                <input type="hidden" name="page" value="1" />
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
            <div class="top-actions" style="margin-bottom:10px; gap:8px;">
                <?php
                $statusButtons = [
                    'all' => ['label' => 'Todos', 'count' => (int) $totalRows],
                    'ok' => ['label' => 'OK', 'count' => (int) ($statusCounts['ok_count'] ?? 0)],
                    'error' => ['label' => 'ERROR', 'count' => (int) ($statusCounts['error_count'] ?? 0)],
                ];
                ?>
                <?php foreach ($statusButtons as $statusKey => $meta): ?>
                    <?php $query = $baseQueryParams; $query['status_filter'] = $statusKey; $query['page'] = '1'; ?>
                    <a class="btn small <?= $statusFilterInput === $statusKey ? 'primary' : '' ?>" href="index.php?<?= h(http_build_query($query)) ?>">
                        <?= h($meta['label']) ?> (<?= h((string) $meta['count']) ?>)
                    </a>
                <?php endforeach; ?>
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
                            <tr data-ip-row="<?= h($row['ip_address']) ?>">
                                <td>
                                    <strong><?= h($row['ip_address']) ?></strong>
                                    <div class="muted js-hostname"><?= h($row['host_name'] ?: '-') ?></div>
                                </td>
                                <td><?= h($row['location'] ?: '-') ?></td>
                                <td>
                                    Alias: <?= h($row['alias'] ?: '-') ?><br>
                                    Nombre: <span class="js-hostname"><?= h($row['host_name'] ?: '-') ?></span><br>
                                Tipo: <?= h($row['host_type'] ?: '-') ?><br>
                                Ubicación: <?= h($row['location'] ?: '-') ?><br>
                                Notas: <?= h($row['notes'] ?: '-') ?><br>
                                Último uptime: <?= h($row['last_uptime'] ?: '-') ?><br>
                                Último visto online: <?= h($row['last_seen_online_at'] ? format_display_datetime($row['last_seen_online_at']) : '-') ?><br>
                                Registrado por: <?= h($row['created_by'] ?: '-') ?>
                            </td>
                                <td class="js-status-cell">
                                    <?php $statusLabel = strtoupper((string) ($row['last_status'] ?: 'SIN DATOS')); ?>
                                    <span class="status-pill js-status-pill <?= $statusLabel === 'OK' ? 'ok' : (($statusLabel === 'ERROR') ? 'error' : 'unknown') ?>"><?= h($statusLabel) ?></span>
                                    <div class="muted js-last-ping"><?= h($row['last_ping_at'] ? format_display_datetime($row['last_ping_at']) : 'Nunca') ?></div>
                                </td>
                                <td class="actions-col">
                                    <a class="btn small" href="index.php?view=ips&amp;action=detail&amp;ip=<?= urlencode($row['ip_address']) ?>">Detalles</a>
                                    <form method="post" class="js-ping-now-form">
                                        <input type="hidden" name="action" value="ping_now">
                                        <input type="hidden" name="ip_address" value="<?= h($row['ip_address']) ?>">
                                        <input type="hidden" name="return_to" value="<?= h($currentUrl) ?>">
                                        <button class="btn small js-ping-btn" type="submit">Ping</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                    </tbody>
                </table>
            </div>
            <div class="card-title-row" style="margin-top:10px;">
                <?php
                $startRow = $totalRows === 0 ? 0 : ($offset + 1);
                $endRow = min($offset + $perPageInput, $totalRows);
                ?>
                <div class="top-actions" style="gap:8px;">
                    <div class="muted">Mostrando <?= h((string) $startRow) ?> a <?= h((string) $endRow) ?> de <?= h((string) $totalRows) ?> filas</div>
                    <form method="get" class="top-actions" style="gap:6px;">
                        <input type="hidden" name="view" value="ips" />
                        <input type="hidden" name="segment" value="<?= h($segmentFilterInput) ?>" />
                        <input type="hidden" name="ip_filter" value="<?= h($ipFilterInput) ?>" />
                        <input type="hidden" name="name_filter" value="<?= h($nameFilterInput) ?>" />
                        <input type="hidden" name="location_filter" value="<?= h($locationFilterInput) ?>" />
                        <input type="hidden" name="status_filter" value="<?= h($statusFilterInput) ?>" />
                        <input type="hidden" name="page" value="1" />
                        <label class="muted" style="margin-top:0;">Filas</label>
                        <select name="per_page" onchange="this.form.submit()" style="width:90px; padding:6px 8px;">
                            <?php foreach ($perPageOptions as $opt): ?>
                                <option value="<?= h((string) $opt) ?>" <?= $perPageInput === $opt ? 'selected' : '' ?>><?= h((string) $opt) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </form>
                </div>
                <div class="top-actions" style="gap:8px;">
                    <?php $prevQuery = $baseQueryParams; $prevQuery['page'] = (string) max(1, $currentPage - 1); ?>
                    <?php $nextQuery = $baseQueryParams; $nextQuery['page'] = (string) min($totalPages, $currentPage + 1); ?>
                    <a class="btn small <?= $currentPage <= 1 ? 'ghost' : '' ?>" href="index.php?<?= h(http_build_query($prevQuery)) ?>">Anterior</a>
                    <span class="pill">Página <?= h((string) $currentPage) ?> / <?= h((string) $totalPages) ?></span>
                    <a class="btn small <?= $currentPage >= $totalPages ? 'ghost' : '' ?>" href="index.php?<?= h(http_build_query($nextQuery)) ?>">Siguiente</a>
                </div>
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
                    <tr><th>Último visto online</th><td><?= h($detail['last_seen_online_at'] ? format_display_datetime($detail['last_seen_online_at']) : '-') ?></td></tr>
                    <tr><th>Último uptime</th><td><?= h($detail['last_uptime'] ?: '-') ?></td></tr>
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

<script>
document.addEventListener('DOMContentLoaded', () => {
    const forms = document.querySelectorAll('.js-ping-now-form');
    forms.forEach((form) => {
        form.addEventListener('submit', async (event) => {
            event.preventDefault();

            const btn = form.querySelector('.js-ping-btn');
            if (!btn) {
                form.submit();
                return;
            }

            const originalLabel = btn.textContent;
            btn.disabled = true;
            btn.textContent = 'Ping...';

            try {
                const response = await fetch('index.php', {
                    method: 'POST',
                    headers: {
                        'Accept': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest',
                    },
                    body: new FormData(form),
                });

                if (!response.ok) {
                    throw new Error('HTTP ' + response.status);
                }

                const data = await response.json();
                if (!data.ok) {
                    throw new Error(data.message || 'No se pudo ejecutar ping');
                }

                const row = form.closest('tr[data-ip-row]');
                if (!row) {
                    return;
                }

                row.querySelectorAll('.js-hostname').forEach((node) => {
                    node.textContent = data.hostname && data.hostname.trim() !== '' ? data.hostname : '-';
                });

                const statusPill = row.querySelector('.js-status-pill');
                if (statusPill) {
                    statusPill.textContent = data.status || 'SIN DATOS';
                    statusPill.classList.remove('ok', 'error', 'unknown');
                    statusPill.classList.add(data.status_class || 'unknown');
                }

                const lastPing = row.querySelector('.js-last-ping');
                if (lastPing) {
                    lastPing.textContent = data.last_ping_at_display || 'Nunca';
                }
            } catch (error) {
                form.submit();
                return;
            } finally {
                btn.disabled = false;
                btn.textContent = originalLabel;
            }
        });
    });
});
</script>
</body>
</html>
