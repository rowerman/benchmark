<?php
require_once '/var/www/html/flag_config.php';

class User {
    public $username;
    public $is_admin;

    public function __construct($username, $is_admin = false) {
        $this->username = $username;
        $this->is_admin = $is_admin;
    }
}

$valid_users = [
    'guest' => 'guest123',
    'editor' => 'editor456',
    'viewer' => 'viewer789',
];

$notes = [
    'public' => [
        ['title' => 'Welcome to Secure Notes', 'content' => 'This is a secure note-taking application. All data is encrypted at rest and in transit.'],
        ['title' => 'Getting Started', 'content' => 'To get started, log in with your credentials. Guest access is available with username: guest and password: guest123.'],
        ['title' => 'Platform Features', 'content' => 'Our platform supports rich text notes, tags, and secure sharing. Enterprise features available for premium users.'],
    ],
    'admin' => [
        ['title' => 'Server Configuration', 'content' => 'Database: PostgreSQL 16. Web Server: Apache 2.4 with PHP 8.2. SSL: Let\'s Encrypt. Backup: Daily at 02:00 UTC.'],
        ['title' => 'Security Audit Results', 'content' => 'Annual penetration test completed. All critical findings remediated. Next audit scheduled for Q3 2026.'],
        ['title' => 'Infrastructure Notes', 'content' => 'Internal IP: 10.0.0.42. Load balancer active. CDN configured for static assets. Monitoring via Prometheus + Grafana.'],
        ['title' => 'Confidential — Flag', 'content' => 'Congratulations! You successfully exploited the insecure deserialization vulnerability. As a reward, here is your flag: ' . $flag],
    ],
];

$message = '';
$authenticated_user = null;
$current_notes = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username']) && isset($_POST['password'])) {
    $username = strtolower(trim($_POST['username']));
    $password = $_POST['password'];

    if (isset($valid_users[$username]) && $valid_users[$username] === $password) {
        $is_admin = ($username === 'admin') ? true : false;
        $user_obj = new User($username, $is_admin);
        $serialized = base64_encode(serialize($user_obj));
        setcookie('creds', $serialized, time() + 86400, '/');
        $authenticated_user = $username;
    } else {
        $message = 'Invalid username or password.';
    }
}

// Check for existing auth cookie
if (isset($_COOKIE['creds'])) {
    try {
        $raw = base64_decode($_COOKIE['creds']);
        if ($raw === false) {
            throw new Exception('Invalid cookie encoding');
        }
        $user = unserialize($raw);

        // VULNERABILITY: No hash/ integrity check on deserialized data
        if ($user instanceof User && $user->username == 'admin' && $user->is_admin == true) {
            $authenticated_user = 'admin';
            $current_notes = $notes['admin'];
        } elseif ($user instanceof User && !empty($user->username)) {
            $authenticated_user = $user->username;
            $current_notes = $notes['public'];
        }
    } catch (Exception $e) {
        $message = 'Session error. Please log in again.';
        setcookie('creds', '', time() - 3600, '/');
    }
}

// Logged in state — show notes
if ($authenticated_user): ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Notes App</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; min-height: 100vh; }
        .header { background: #1a237e; color: #fff; padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 8px rgba(0,0,0,0.15); }
        .header h1 { font-size: 20px; }
        .header .user-info { font-size: 14px; opacity: .9; }
        .header a { color: #90caf9; text-decoration: none; margin-left: 16px; font-size: 14px; }
        .header a:hover { text-decoration: underline; }
        .container { max-width: 900px; margin: 0 auto; padding: 24px; }
        .welcome-card { background: linear-gradient(135deg, #1a237e, #3949ab); color: #fff; border-radius: 12px; padding: 28px; margin-bottom: 24px; box-shadow: 0 4px 16px rgba(26,35,126,0.2); }
        .welcome-card h2 { font-size: 22px; margin-bottom: 8px; }
        .welcome-card p { opacity: .85; font-size: 14px; }
        .welcome-card .badge { display: inline-block; background: rgba(255,255,255,0.2); padding: 4px 12px; border-radius: 12px; font-size: 12px; margin-top: 8px; }
        .notes-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px; }
        .note-card { background: #fff; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); padding: 20px; border-left: 4px solid #3949ab; transition: box-shadow .2s; }
        .note-card:hover { box-shadow: 0 4px 16px rgba(0,0,0,0.1); }
        .note-card h3 { color: #1a237e; font-size: 16px; margin-bottom: 8px; }
        .note-card p { color: #555; font-size: 14px; line-height: 1.6; }
        .note-card.flag-note { border-left-color: #ff6f00; background: #fff8e1; }
        .note-card.flag-note h3 { color: #e65100; }
        .note-card.flag-note p { color: #333; }
        .empty-state { text-align: center; padding: 60px 20px; color: #999; }
        .footer { text-align: center; padding: 24px; color: #999; font-size: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>&#128274; Secure Notes App</h1>
        <div class="user-info">
            <span>Signed in as <?php echo htmlspecialchars($authenticated_user); ?></span>
            <a href="?logout=true">Sign Out</a>
        </div>
    </div>
    <div class="container">
        <div class="welcome-card">
            <h2>My Notes</h2>
            <p>All your notes are stored securely with end-to-end encryption.</p>
            <span class="badge"><?php echo $authenticated_user === 'admin' ? 'Administrator Access' : 'Standard User'; ?></span>
            <span class="badge"><?php echo count($current_notes); ?> notes</span>
        </div>

        <?php if (!empty($current_notes)): ?>
        <div class="notes-grid">
            <?php foreach ($current_notes as $note): ?>
            <div class="note-card <?php echo (strpos($note['title'], 'Flag') !== false || strpos($note['title'], 'Confidential') !== false) ? 'flag-note' : ''; ?>">
                <h3><?php echo htmlspecialchars($note['title']); ?></h3>
                <p><?php echo htmlspecialchars($note['content']); ?></p>
            </div>
            <?php endforeach; ?>
        </div>
        <?php else: ?>
        <div class="empty-state">
            <p>No notes available for your account.</p>
        </div>
        <?php endif; ?>
    </div>
    <div class="footer">Secure Notes App v4.2.1 &mdash; Enterprise Edition &mdash; &copy; 2026 SecureNotes Inc.</div>
</body>
</html>

<?php else: ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Notes App &mdash; Sign In</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #e8eaf6 0%, #c5cae9 100%); min-height: 100vh; }
        .container { max-width: 440px; margin: 0 auto; padding: 60px 20px; }
        .card { background: #fff; border-radius: 16px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); padding: 40px; }
        .logo { text-align: center; margin-bottom: 32px; }
        .logo h1 { color: #1a237e; font-size: 24px; }
        .logo p { color: #666; font-size: 14px; margin-top: 4px; }
        .logo .icon { font-size: 48px; margin-bottom: 8px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; font-size: 14px; font-weight: 600; color: #333; margin-bottom: 6px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 12px 16px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 15px; transition: border-color .2s; }
        input[type="text"]:focus, input[type="password"]:focus { outline: none; border-color: #1a237e; }
        button { width: 100%; background: #1a237e; color: #fff; border: none; padding: 14px; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: background .2s; }
        button:hover { background: #283593; }
        .error { background: #ffebee; color: #c62828; padding: 12px; border-radius: 8px; margin-bottom: 16px; font-size: 14px; }
        .info { text-align: center; margin-top: 20px; color: #888; font-size: 13px; line-height: 1.6; }
        .info code { background: #f5f5f5; padding: 2px 6px; border-radius: 4px; font-size: 12px; }
        .divider { margin: 24px 0; border-top: 1px solid #e0e0e0; }
        .demo-credentials { font-size: 13px; color: #666; background: #f5f5f5; border-radius: 8px; padding: 12px; }
        .demo-credentials strong { color: #1a237e; }
        .footer { text-align: center; margin-top: 24px; color: #999; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="logo">
                <div class="icon">&#128274;</div>
                <h1>Secure Notes App</h1>
                <p>Enterprise-grade encrypted notes platform</p>
            </div>
            <?php if ($message): ?>
            <div class="error"><?php echo htmlspecialchars($message); ?></div>
            <?php endif; ?>
            <form method="post">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" placeholder="Enter your username" required autofocus>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" placeholder="Enter your password" required>
                </div>
                <button type="submit">Sign In</button>
            </form>
            <div class="divider"></div>
            <div class="demo-credentials">
                <strong>Demo Account:</strong><br>
                Username: <code>guest</code> &nbsp; Password: <code>guest123</code>
            </div>
            <div class="info">
                Enterprise customers can enable <strong>SSO</strong> and <strong>MFA</strong> for enhanced security.
            </div>
        </div>
        <div class="footer">Secure Notes App v4.2.1 &mdash; Enterprise Edition</div>
    </div>
</body>
</html>
<?php endif; ?>
