<?php
/**
 * Shell Scanner Detector - single file defensive scanner
 * - Recursively scans directories for suspicious PHP/webshell/backdoor patterns.
 * - Lists suspects with reasons.
 * - View full code with highlighted indicators.
 * - Delete selected / delete all suspects (with CSRF protection).
 * - Optional quarantine (move to a quarantine folder).
 *
 * Usage:
 * 1) Upload this file to your web root (or a private folder).
 * 2) Open in browser: https://yoursite.com/shell-scanner.php
 * 3) Run scan -> View -> Delete/Quarantine
 *
 * Recommended: protect access via .htaccess or IP allowlist.
 */

declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', '0');
header('X-Content-Type-Options: nosniff');

session_start();

// ------------------- CONFIG -------------------
$CONFIG = [
    // Root folder to scan (default: current directory)
    'scan_root' => realpath(__DIR__),

    // Max file size to read (bytes) to avoid huge files
    'max_bytes' => 2 * 1024 * 1024, // 2MB

    // Extensions to scan
    'extensions' => ['php', 'phtml', 'php5', 'php7', 'inc', 'txt', 'htaccess'],

    // Ignore folders (substring match)
    'ignore_dirs' => [
        DIRECTORY_SEPARATOR . 'node_modules' . DIRECTORY_SEPARATOR,
        DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR,
        DIRECTORY_SEPARATOR . '.git' . DIRECTORY_SEPARATOR,
        DIRECTORY_SEPARATOR . 'cache' . DIRECTORY_SEPARATOR,
        DIRECTORY_SEPARATOR . 'tmp' . DIRECTORY_SEPARATOR,
        DIRECTORY_SEPARATOR . 'logs' . DIRECTORY_SEPARATOR,
        DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'cache' . DIRECTORY_SEPARATOR,
    ],

    // Quarantine folder (created under scan_root)
    'quarantine_dir_name' => '_quarantine_shell_scanner',

    // Optional: require a simple password (set to '' to disable)
    'password' => '', // e.g. 'ChangeMe123!'
];

// ------------------- AUTH (optional) -------------------
if ($CONFIG['password'] !== '') {
    if (!isset($_SESSION['ssd_authed']) || $_SESSION['ssd_authed'] !== true) {
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
            if (hash_equals($CONFIG['password'], (string)$_POST['password'])) {
                $_SESSION['ssd_authed'] = true;
                header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
                exit;
            }
            $auth_error = "Wrong password";
        }
        echo "<!doctype html><meta charset='utf-8'><title>Shell Scanner - Login</title>
        <style>body{font-family:system-ui,Segoe UI,Arial;margin:40px}input{padding:10px;font-size:16px}</style>
        <h2>Shell Scanner Detector</h2>
        <p>Enter password to continue.</p>
        " . (!empty($auth_error) ? "<p style='color:#b00'><b>$auth_error</b></p>" : "") . "
        <form method='post'>
            <input type='password' name='password' placeholder='Password' required>
            <button type='submit'>Login</button>
        </form>";
        exit;
    }
}

// ------------------- HELPERS -------------------
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

function csrf_token(): string {
    if (empty($_SESSION['ssd_csrf'])) $_SESSION['ssd_csrf'] = bin2hex(random_bytes(16));
    return $_SESSION['ssd_csrf'];
}
function csrf_check(): void {
    $t = $_POST['csrf'] ?? '';
    if (empty($_SESSION['ssd_csrf']) || !is_string($t) || !hash_equals($_SESSION['ssd_csrf'], $t)) {
        http_response_code(403);
        exit("CSRF check failed.");
    }
}

function is_within_root(string $path, string $root): bool {
    $rp = realpath($path);
    $rr = realpath($root);
    if ($rp === false || $rr === false) return false;
    return strpos($rp, $rr) === 0;
}

function normalize_path(string $path): string {
    return str_replace(['\\', '//'], ['/', '/'], $path);
}

function get_patterns(): array {
    // Indicators: keep defensive-oriented, common malicious behaviors
    // Each item: [label, regex, severity]
    return [
        ['Remote code exec: eval',               '/\beval\s*\(/i', 'high'],
        ['Remote code exec: assert',             '/\bassert\s*\(/i', 'high'],
        ['Obfuscation: base64_decode',           '/\bbase64_decode\s*\(/i', 'med'],
        ['Obfuscation: gzinflate/gzuncompress',  '/\bgzinflate\s*\(|\bgzuncompress\s*\(/i', 'med'],
        ['Obfuscation: str_rot13',               '/\bstr_rot13\s*\(/i', 'low'],
        ['Dynamic call: call_user_func',         '/\bcall_user_func(_array)?\s*\(/i', 'med'],
        ['Dangerous: preg_replace /e',           '/preg_replace\s*\(\s*[\'"][^\'"]*\/e[^\'"]*[\'"]/i', 'high'],
        ['Command exec: system/exec/shell_exec', '/\b(system|exec|shell_exec|passthru|proc_open|popen)\s*\(/i', 'high'],
        ['File write: file_put_contents',        '/\bfile_put_contents\s*\(/i', 'med'],
        ['File write: fopen/fwrite',             '/\bfopen\s*\(|\bfwrite\s*\(/i', 'med'],
        ['Network: curl_init',                   '/\bcurl_(init|exec|setopt)\s*\(/i', 'med'],
        ['Network: fsockopen',                   '/\bfsockopen\s*\(/i', 'med'],
        ['Network: wp_remote_get/post',          '/\bwp_remote_(get|post)\s*\(/i', 'med'],
        ['Superglobals used (common in shells)', '/\$_(GET|POST|REQUEST|COOKIE)\b/i', 'low'],

        // Specific IoCs from your sample (Hello Joy loader)
        ['IOC: XOR key nElNHi',                  '/nElNHi/', 'high'],
        ['IOC: base64 id GHFCOTgIAmseOw==',      '/GHFCOTgIAmseOw==/', 'high'],
        ['IOC: base64 id GHFCOThYXHZCPD0=',      '/GHFCOThYXHZCPD0=/', 'high'],
        ['IOC: base64 id GHFCJiEeHmseOw==',      '/GHFCJiEeHmseOw==/', 'high'],
        ['IOC: /v5 endpoint',                    '/\/v5\b/', 'med'],

        // Common webshell markers (strings often seen)
        ['Shell marker: "Shell Bypass"',         '/Shell\s*Bypass/i', 'high'],
        ['Shell marker: "xNeonn"',               '/xNeonn/i', 'high'],
        ['Shell marker: "FilesMan"',             '/FilesMan/i', 'high'],
        ['Shell marker: "WSO"',                  '/\bWSO\b/i', 'high'],
    ];
}

function severity_score(string $sev): int {
    return $sev === 'high' ? 3 : ($sev === 'med' ? 2 : 1);
}

function sha256_file_safe(string $path, int $maxBytes): string {
    $size = @filesize($path);
    if ($size === false) return '';
    // hash full file if not huge; otherwise hash first maxBytes (still useful)
    if ($size <= $maxBytes) return hash_file('sha256', $path) ?: '';
    $fh = @fopen($path, 'rb');
    if (!$fh) return '';
    $data = fread($fh, $maxBytes);
    fclose($fh);
    return hash('sha256', $data ?: '');
}

function read_file_limited(string $path, int $maxBytes): string {
    $size = @filesize($path);
    if ($size === false) return '';
    if ($size > $maxBytes) {
        $fh = @fopen($path, 'rb');
        if (!$fh) return '';
        $data = fread($fh, $maxBytes);
        fclose($fh);
        return (string)$data;
    }
    $data = @file_get_contents($path);
    return $data === false ? '' : $data;
}

function scan(string $root, array $config): array {
    $patterns = get_patterns();
    $exts = array_map('strtolower', $config['extensions']);
    $ignore = $config['ignore_dirs'];

    $suspects = [];
    $checked = 0;

    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
    );

    foreach ($it as $fileInfo) {
        /** @var SplFileInfo $fileInfo */
        if (!$fileInfo->isFile()) continue;

        $path = $fileInfo->getPathname();
        $pathNorm = normalize_path($path);

        // ignore dirs
        $skip = false;
        foreach ($ignore as $badDir) {
            if (strpos($pathNorm, normalize_path($badDir)) !== false) { $skip = true; break; }
        }
        if ($skip) continue;

        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        if (!in_array($ext, $exts, true)) continue;

        $checked++;
        $content = read_file_limited($path, $config['max_bytes']);
        if ($content === '') continue;

        $reasons = [];
        $score = 0;

        // Heuristic: long single line (obfuscation)
        foreach (preg_split("/\r\n|\n|\r/", $content) as $ln) {
            if (strlen($ln) > 25000) {
                $reasons[] = ['Very long line (possible obfuscation)', 'med', 'line'];
                $score += severity_score('med');
                break;
            }
        }

        // Match patterns
        foreach ($patterns as [$label, $regex, $sev]) {
            if (preg_match($regex, $content)) {
                $reasons[] = [$label, $sev, $regex];
                $score += severity_score($sev);
            }
        }

        // Strong combo: base64_decode + eval/assert
        $combo = (stripos($content, 'base64_decode(') !== false) &&
                 ((stripos($content, 'eval(') !== false) || (stripos($content, 'assert(') !== false));
        if ($combo) {
            $reasons[] = ['Combo: base64_decode + eval/assert', 'high', 'combo'];
            $score += severity_score('high');
        }

        if (!empty($reasons)) {
            $suspects[] = [
                'path' => $pathNorm,
                'size' => (int)@filesize($path),
                'mtime' => (int)@filemtime($path),
                'sha256' => sha256_file_safe($path, $config['max_bytes']),
                'score' => $score,
                'reasons' => $reasons,
            ];
        }
    }

    // Sort by score desc, then mtime desc
    usort($suspects, function($a, $b){
        if ($a['score'] !== $b['score']) return $b['score'] <=> $a['score'];
        return ($b['mtime'] ?? 0) <=> ($a['mtime'] ?? 0);
    });

    return [
        'time' => date('c'),
        'root' => normalize_path($root),
        'checked' => $checked,
        'suspects' => $suspects,
    ];
}

function highlight_code(string $code, array $reasons): string {
    // Build highlight regex list from reasons, but keep safe.
    $regexes = [];
    foreach ($reasons as $r) {
        // $r[2] contains regex or 'combo'/'line'
        if (is_string($r[2]) && $r[2] !== 'combo' && $r[2] !== 'line') {
            $regexes[] = $r[2];
        }
    }
    // fallback highlights for key tokens
    $fallback = [
        '/\beval\s*\(/i',
        '/\bbase64_decode\s*\(/i',
        '/\bgzinflate\s*\(/i',
        '/\bgzuncompress\s*\(/i',
        '/\b(system|exec|shell_exec|passthru|proc_open|popen)\s*\(/i',
        '/\bwp_remote_(get|post)\s*\(/i',
        '/nElNHi/',
        '/GHFCOTgIAmseOw==/',
        '/GHFCOThYXHZCPD0=/',
        '/GHFCJiEeHmseOw==/',
        '/Shell\s*Bypass/i',
        '/xNeonn/i',
    ];
    $regexes = array_merge($regexes, $fallback);
    $regexes = array_values(array_unique($regexes));

    $safe = h($code);
    // Highlight by applying regex to the original code but output escaped segments.
    // We'll do a simple token highlight by replacing on escaped content too:
    foreach ($regexes as $rx) {
        // apply on escaped text is okay for these ASCII patterns
        $safe = preg_replace($rx, '<mark>$0</mark>', $safe);
    }
    return $safe;
}

function quarantine_files(array $paths, array $config): array {
    $root = $config['scan_root'];
    $qdir = $root . DIRECTORY_SEPARATOR . $config['quarantine_dir_name'] . '_' . date('Ymd_His');

    if (!is_dir($qdir) && !@mkdir($qdir, 0755, true)) {
        return ['ok' => false, 'msg' => 'Cannot create quarantine directory: ' . $qdir];
    }
    @file_put_contents($qdir . DIRECTORY_SEPARATOR . 'README.txt', "Quarantined by Shell Scanner Detector at " . date('c') . "\n");
    @file_put_contents($qdir . DIRECTORY_SEPARATOR . '.htaccess', "Deny from all\n");

    $moved = 0;
    $failed = [];

    foreach ($paths as $p) {
        $real = realpath($p);
        if ($real === false || !is_within_root($real, $root)) { $failed[] = $p; continue; }
        $dest = $qdir . DIRECTORY_SEPARATOR . basename($real) . '.quarantined';
        if (@rename($real, $dest)) $moved++;
        else $failed[] = $p;
    }
    return ['ok' => true, 'moved' => $moved, 'failed' => $failed, 'qdir' => $qdir];
}

function delete_files(array $paths, array $config): array {
    $root = $config['scan_root'];
    $deleted = 0;
    $failed = [];

    foreach ($paths as $p) {
        $real = realpath($p);
        if ($real === false || !is_within_root($real, $root)) { $failed[] = $p; continue; }
        if (@unlink($real)) $deleted++;
        else $failed[] = $p;
    }
    return ['deleted' => $deleted, 'failed' => $failed];
}

// ------------------- ACTIONS -------------------
$action = $_GET['action'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();

    if (isset($_POST['do_scan'])) {
        $root = $CONFIG['scan_root'];
        $res = scan($root, $CONFIG);
        $_SESSION['ssd_last'] = $res;
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    }

    if (isset($_POST['do_delete_selected'])) {
        $files = $_POST['files'] ?? [];
        $files = is_array($files) ? array_map('strval', $files) : [];
        $result = delete_files($files, $CONFIG);
        $_SESSION['ssd_msg'] = "Deleted {$result['deleted']} file(s). Failed: " . count($result['failed']);
        $_SESSION['ssd_failed'] = $result['failed'];
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    }

    if (isset($_POST['do_delete_all'])) {
        $last = $_SESSION['ssd_last']['suspects'] ?? [];
        $paths = array_map(fn($s)=>$s['path'], $last);
        $result = delete_files($paths, $CONFIG);
        $_SESSION['ssd_msg'] = "Deleted {$result['deleted']} suspicious file(s). Failed: " . count($result['failed']);
        $_SESSION['ssd_failed'] = $result['failed'];
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    }

    if (isset($_POST['do_quarantine_selected'])) {
        $files = $_POST['files'] ?? [];
        $files = is_array($files) ? array_map('strval', $files) : [];
        $q = quarantine_files($files, $CONFIG);
        $_SESSION['ssd_msg'] = $q['ok']
            ? "Quarantined {$q['moved']} file(s) to: {$q['qdir']}. Failed: " . count($q['failed'])
            : $q['msg'];
        $_SESSION['ssd_failed'] = $q['failed'] ?? [];
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    }

    if (isset($_POST['do_quarantine_all'])) {
        $last = $_SESSION['ssd_last']['suspects'] ?? [];
        $paths = array_map(fn($s)=>$s['path'], $last);
        $q = quarantine_files($paths, $CONFIG);
        $_SESSION['ssd_msg'] = $q['ok']
            ? "Quarantined {$q['moved']} suspicious file(s) to: {$q['qdir']}. Failed: " . count($q['failed'])
            : $q['msg'];
        $_SESSION['ssd_failed'] = $q['failed'] ?? [];
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    }
}

// ------------------- UI -------------------
$last = $_SESSION['ssd_last'] ?? null;
$msg = $_SESSION['ssd_msg'] ?? '';
$failed = $_SESSION['ssd_failed'] ?? [];
unset($_SESSION['ssd_msg'], $_SESSION['ssd_failed']);

?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Shell Scanner Detector</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;margin:20px;line-height:1.35}
    .wrap{max-width:1200px;margin:auto}
    .card{border:1px solid #ddd;border-radius:10px;padding:16px;margin:12px 0}
    button{padding:10px 14px;font-size:14px;border-radius:8px;border:1px solid #bbb;background:#f7f7f7;cursor:pointer}
    button.primary{background:#1f6feb;border-color:#1f6feb;color:#fff}
    button.danger{background:#b00020;border-color:#b00020;color:#fff}
    button.warn{background:#b36b00;border-color:#b36b00;color:#fff}
    table{border-collapse:collapse;width:100%}
    th,td{border-bottom:1px solid #eee;padding:10px;vertical-align:top}
    th{background:#fafafa;text-align:left}
    code, pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
    pre{white-space:pre-wrap;word-break:break-word;background:#0b1020;color:#d7e0ff;padding:12px;border-radius:10px;overflow:auto}
    mark{background:#ffe58f;padding:0 2px;border-radius:3px}
    .sev{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;border:1px solid #ddd}
    .sev.high{background:#ffebee;border-color:#ffcdd2}
    .sev.med{background:#fff8e1;border-color:#ffe0b2}
    .sev.low{background:#e8f5e9;border-color:#c8e6c9}
    .muted{color:#666}
    .row{display:flex;gap:10px;flex-wrap:wrap}
    .row > * {flex:0 0 auto}
    a.btn{display:inline-block;padding:8px 12px;border-radius:8px;border:1px solid #bbb;background:#fff;text-decoration:none;color:#111}
    .topbar{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
</style>
</head>
<body>
<div class="wrap">
    <div class="topbar">
        <h2>Shell Scanner Detector</h2>
        <div class="muted">Scan root: <code><?php echo h((string)$CONFIG['scan_root']); ?></code></div>
    </div>

    <?php if ($msg): ?>
        <div class="card" style="border-color:#bde0c0;background:#f2fff5">
            <b><?php echo h($msg); ?></b>
            <?php if (!empty($failed)): ?>
                <div class="muted">Failed paths:</div>
                <ul><?php foreach ($failed as $f) echo '<li><code>'.h($f).'</code></li>'; ?></ul>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <div class="card">
        <form method="post">
            <input type="hidden" name="csrf" value="<?php echo h(csrf_token()); ?>">
            <div class="row">
                <button class="primary" type="submit" name="do_scan" value="1">Run Scan</button>
                <span class="muted">Scans recursively and flags suspicious files using multiple indicators.</span>
            </div>
        </form>
    </div>

<?php
// View file action
if ($action === 'view') {
    $file = $_GET['file'] ?? '';
    $file = is_string($file) ? $file : '';
    $real = realpath($file);

    if ($real === false || !is_within_root($real, $CONFIG['scan_root'])) {
        echo "<div class='card'><b style='color:#b00'>Invalid file.</b></div>";
    } else {
        $content = read_file_limited($real, $CONFIG['max_bytes']);
        // Find reasons from last scan, if any:
        $reasons = [];
        if (!empty($last['suspects'])) {
            foreach ($last['suspects'] as $s) {
                if (normalize_path($s['path']) === normalize_path($real)) {
                    $reasons = $s['reasons'];
                    break;
                }
            }
        }
        if (empty($reasons)) {
            // fallback reasons by matching patterns now
            foreach (get_patterns() as $p) {
                if (preg_match($p[1], $content)) $reasons[] = [$p[0], $p[2], $p[1]];
            }
        }

        echo "<div class='card'>";
        echo "<div class='row' style='justify-content:space-between;align-items:center'>";
        echo "<div><b>Viewing:</b> <code>" . h(normalize_path($real)) . "</code></div>";
        echo "<div><a class='btn' href='" . h(strtok($_SERVER['REQUEST_URI'], '?')) . "'>← Back</a></div>";
        echo "</div>";

        if (!empty($reasons)) {
            echo "<p><b>Indicators:</b></p><ul>";
            foreach ($reasons as $r) {
                $sev = $r[1];
                echo "<li><span class='sev ".h($sev)."'>".h($sev)."</span> ".h($r[0])."</li>";
            }
            echo "</ul>";
        }

        $hl = highlight_code($content, $reasons);
        echo "<pre>$hl</pre>";
        echo "</div>";
    }
}
?>

<?php if ($action !== 'view'): ?>
    <div class="card">
        <h3>Results</h3>
        <?php if (!$last): ?>
            <p class="muted">No scan yet. Click <b>Run Scan</b>.</p>
        <?php else: ?>
            <p>
                Scanned at: <code><?php echo h($last['time'] ?? ''); ?></code><br>
                Files checked: <code><?php echo (int)($last['checked'] ?? 0); ?></code><br>
                Suspects found: <code><?php echo isset($last['suspects']) ? count($last['suspects']) : 0; ?></code>
            </p>

            <?php if (!empty($last['suspects'])): ?>
                <form method="post" onsubmit="return confirm('Are you sure?');">
                    <input type="hidden" name="csrf" value="<?php echo h(csrf_token()); ?>">

                    <div class="row" style="margin:10px 0">
                        <button class="danger" type="submit" name="do_delete_selected" value="1">Delete Selected</button>
                        <button class="danger" type="submit" name="do_delete_all" value="1">Delete ALL Suspects</button>
                        <button class="warn" type="submit" name="do_quarantine_selected" value="1">Quarantine Selected</button>
                        <button class="warn" type="submit" name="do_quarantine_all" value="1">Quarantine ALL Suspects</button>
                        <span class="muted">Tip: Quarantine is safer than delete.</span>
                    </div>

                    <table>
                        <thead>
                            <tr>
                                <th style="width:34px"><input type="checkbox" onclick="toggleAll(this)"></th>
                                <th>File</th>
                                <th>Indicators</th>
                                <th style="width:90px">Score</th>
                                <th style="width:160px">Modified</th>
                                <th style="width:120px">SHA256</th>
                                <th style="width:90px">View</th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($last['suspects'] as $s): ?>
                            <?php
                                $path = (string)$s['path'];
                                $reasons = $s['reasons'] ?? [];
                                $score = (int)($s['score'] ?? 0);
                                $mtime = (int)($s['mtime'] ?? 0);
                                $sha = (string)($s['sha256'] ?? '');
                            ?>
                            <tr>
                                <td><input type="checkbox" name="files[]" value="<?php echo h($path); ?>"></td>
                                <td><code><?php echo h($path); ?></code><br><span class="muted"><?php echo (int)($s['size'] ?? 0); ?> bytes</span></td>
                                <td>
                                    <ul style="margin:0;padding-left:18px">
                                        <?php foreach ($reasons as $r): ?>
                                            <?php $sev = $r[1] ?? 'low'; ?>
                                            <li><span class="sev <?php echo h($sev); ?>"><?php echo h($sev); ?></span> <?php echo h($r[0] ?? ''); ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                </td>
                                <td><b><?php echo $score; ?></b></td>
                                <td><code><?php echo $mtime ? h(date('Y-m-d H:i:s', $mtime)) : ''; ?></code></td>
                                <td><code style="font-size:12px"><?php echo h(substr($sha, 0, 16)) . '…'; ?></code></td>
                                <td>
                                    <a class="btn" href="?action=view&file=<?php echo urlencode($path); ?>">View</a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </form>
            <?php else: ?>
                <p class="muted">No suspects found.</p>
            <?php endif; ?>
        <?php endif; ?>
    </div>
<?php endif; ?>

    <div class="card">
        <h3>What it flags</h3>
        <p class="muted">
            This scanner uses indicator-based detection (eval/base64/gzinflate, command execution, suspicious network calls, known IoCs like <code>nElNHi</code> and the base64 strings from the loader).
            Results are heuristic—review with <b>View</b> before deleting.
        </p>
    </div>
</div>

<script>
function toggleAll(master){
  document.querySelectorAll('input[type="checkbox"][name="files[]"]').forEach(cb => cb.checked = master.checked);
}
</script>
</body>
</html>
