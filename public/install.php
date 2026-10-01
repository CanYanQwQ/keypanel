<?php

/**
 * ============================================================================
 *  卡密系统 —— 安装向导
 *
 *  首次访问时填写数据库信息与管理员账号，自动完成：
 *    1. 生成 APP_KEY（写入 .env）
 *    2. 写入数据库配置（写入 .env）
 *    3. 创建数据库（若不存在）
 *    4. 执行数据表迁移
 *    5. 创建管理员账号
 *    6. 写入默认系统设置
 *    7. 生成 install.lock 防止重复安装
 *
 *  安装完成后请**立即删除本文件**。
 *
 *  使用方式：
 *    浏览器访问 http://你的域名/install.php
 * ============================================================================
 */

declare(strict_types=1);

// ---------------------------------------------------------------------------
//  基础环境
// ---------------------------------------------------------------------------
error_reporting(E_ALL);
ini_set('display_errors', '0');   // 出错时用自定义页面，避免泄露路径

// 本文件位于 public/ 目录下，项目根目录是它的上一级。
// 若被移动过位置，则向上查找直到找到 artisan 文件。
define('PUBLIC_PATH', __DIR__);
define('BASE_PATH', locateBasePath());
define('ENV_FILE', BASE_PATH . '/.env');
define('ENV_EXAMPLE', BASE_PATH . '/.env.example');
define('LOCK_FILE', BASE_PATH . '/install.lock');
define('MIN_PHP', '8.2.0');

/**
 * 定位 Laravel 项目根目录（含 artisan 的那一级）。
 */
function locateBasePath(): string
{
    $dir = __DIR__;

    for ($i = 0; $i < 5; $i++) {
        if (is_file($dir . '/artisan')) {
            return $dir;
        }
        $parent = dirname($dir);
        if ($parent === $dir) {
            break;
        }
        $dir = $parent;
    }

    // 兜底：默认认为在 public/ 下
    return dirname(__DIR__);
}

// 防止安装页被搜索引擎收录，并禁止被 iframe 嵌套
if (!headers_sent()) {
    header('X-Robots-Tag: noindex, nofollow, noarchive');
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
}

session_start();

// ---------------------------------------------------------------------------
//  已安装则拒绝再次进入
//
//  安全说明：这里**不提供**任何 URL 参数形式的绕过开关。
//  安装向导本身没有身份校验，若允许通过 URL 强制进入，
//  等于把「重置数据库」的能力开放给任何能访问该地址的人。
//  如需重装，必须手动删除 install.lock 文件（需服务器文件权限）。
// ---------------------------------------------------------------------------
if (file_exists(LOCK_FILE)) {
    renderPage('已安装', function () {
        ?>
        <div class="alert alert-warning">
            <strong>系统已安装。</strong>
            <p>检测到 <code>install.lock</code> 文件，安装向导已锁定。</p>
            <p>如需重新安装，请先在服务器上手动删除根目录下的
               <code>install.lock</code> 文件，然后刷新本页。</p>
            <p class="muted">
                安全提示：安装完成后请立即删除本文件（install.php），
                否则任何能访问该地址的人都可以重置你的数据库。
            </p>
        </div>
        <?php
    });
    exit;
}

// ---------------------------------------------------------------------------
//  环境检查
// ---------------------------------------------------------------------------
$checks = runEnvironmentChecks();
$envOk = !in_array(false, array_column($checks, 'ok'), true);

// ---------------------------------------------------------------------------
//  处理提交
// ---------------------------------------------------------------------------
$errors = [];
$success = false;
$installLog = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $envOk) {
    $input = [
        'db_host'     => trim((string) ($_POST['db_host'] ?? '127.0.0.1')),
        'db_port'     => trim((string) ($_POST['db_port'] ?? '3306')),
        'db_name'     => trim((string) ($_POST['db_name'] ?? '')),
        'db_user'     => trim((string) ($_POST['db_user'] ?? '')),
        'db_pass'     => (string) ($_POST['db_pass'] ?? ''),
        'admin_name'  => trim((string) ($_POST['admin_name'] ?? '')),
        'admin_email' => trim((string) ($_POST['admin_email'] ?? '')),
        'admin_pass'  => (string) ($_POST['admin_pass'] ?? ''),
        'admin_pass2' => (string) ($_POST['admin_pass2'] ?? ''),
        'app_url'     => rtrim(trim((string) ($_POST['app_url'] ?? '')), '/'),
        'app_name'    => trim((string) ($_POST['app_name'] ?? '卡密管理系统')),
        'brand_name'  => trim((string) ($_POST['brand_name'] ?? '卡密管理系统')),
        'backup_pass' => (string) ($_POST['backup_pass'] ?? ''),
    ];

    // ---- 校验 ----
    if ($input['db_name'] === '') {
        $errors[] = '数据库名不能为空。';
    }
    if ($input['db_user'] === '') {
        $errors[] = '数据库用户名不能为空。';
    }
    if (!ctype_digit($input['db_port']) || (int) $input['db_port'] < 1 || (int) $input['db_port'] > 65535) {
        $errors[] = '数据库端口不合法。';
    }
    if ($input['admin_name'] === '') {
        $errors[] = '管理员用户名不能为空。';
    }
    if (!filter_var($input['admin_email'], FILTER_VALIDATE_EMAIL)) {
        $errors[] = '管理员邮箱格式不正确。';
    }
    if (strlen($input['admin_pass']) < 8) {
        $errors[] = '管理员密码至少 8 位。';
    }
    if ($input['admin_pass'] !== $input['admin_pass2']) {
        $errors[] = '两次输入的密码不一致。';
    }
    if ($input['app_url'] === '') {
        $errors[] = '站点地址不能为空。';
    }

    // ---- 连接数据库 ----
    $pdo = null;
    if (empty($errors)) {
        try {
            $dsn = sprintf(
                'mysql:host=%s;port=%s;charset=utf8mb4',
                $input['db_host'],
                $input['db_port']
            );
            $pdo = new PDO($dsn, $input['db_user'], $input['db_pass'], [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_TIMEOUT => 5,
            ]);
            $installLog[] = '数据库连接成功';

            // 数据库不存在则创建
            $dbName = str_replace('`', '', $input['db_name']);
            $pdo->exec("CREATE DATABASE IF NOT EXISTS `{$dbName}` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
            $pdo->exec("USE `{$dbName}`");
            $installLog[] = "数据库 {$dbName} 就绪";

            // 检查是否已有数据表（防止覆盖已有数据）
            $tables = $pdo->query('SHOW TABLES')->fetchAll(PDO::FETCH_COLUMN);
            if (!empty($tables)) {
                $errors[] = '目标数据库中已存在 ' . count($tables) . ' 张表。'
                    . '为避免覆盖数据，安装已中止。请使用空数据库，或先手动清空。';
            }
        } catch (PDOException $e) {
            $errors[] = '数据库连接失败：' . $e->getMessage();
        }
    }

    // ---- 执行安装 ----
    if (empty($errors)) {
        try {
            // 1. 写入 .env
            writeEnvFile($input);
            $installLog[] = '.env 配置已写入';

            // 2. 生成 APP_KEY
            $appKey = 'base64:' . base64_encode(random_bytes(32));
            updateEnvValue('APP_KEY', $appKey);
            $installLog[] = 'APP_KEY 已生成';

            // 3. 引导 Laravel
            //
            // 关键顺序：必须先写完 .env（含 APP_KEY 与数据库配置）再 bootstrap，
            // 这样内核从一开始就读到正确的配置。若在 bootstrap 之后才改配置，
            // 进程内已缓存的 config 与数据库连接会指向旧值，导致后续操作落错库。
            require BASE_PATH . '/vendor/autoload.php';

            // 清掉可能存在的旧配置缓存，确保读到刚写入的 .env
            @unlink(BASE_PATH . '/bootstrap/cache/config.php');
            @unlink(BASE_PATH . '/bootstrap/cache/routes-v7.php');

            $app = require BASE_PATH . '/bootstrap/app.php';
            $kernel = $app->make(Illuminate\Contracts\Console\Kernel::class);
            $kernel->bootstrap();

            $installLog[] = 'Laravel 已引导';

            // 4. 执行数据表迁移
            $exitCode = $kernel->call('migrate', ['--force' => true]);
            if ($exitCode !== 0) {
                throw new RuntimeException('数据表迁移失败：' . $kernel->output());
            }
            $installLog[] = '数据表迁移完成';

            // 5. 创建管理员
            $userClass = \App\Models\User::class;
            if ($userClass::where('email', $input['admin_email'])->exists()) {
                $userClass::where('email', $input['admin_email'])->delete();
            }
            $admin = $userClass::create([
                'name'                 => $input['admin_name'],
                'email'                => $input['admin_email'],
                'password'             => $input['admin_pass'],
                'password_changed_at'  => now(),
                'email_verified_at'    => now(),
            ]);
            $installLog[] = '管理员账号已创建';

            // 6. 写入默认系统设置
            $settings = \App\Services\SettingsService::definitions();
            foreach ($settings as $key => $definition) {
                \App\Services\SettingsService::set($key, $definition['default']);
            }
            \App\Services\SettingsService::flush();
            $installLog[] = '系统设置已初始化（' . count($settings) . ' 项）';

            // 7. 覆盖品牌名
            if ($input['brand_name'] !== '') {
                \App\Services\SettingsService::set('app.brand_name', $input['brand_name']);
            }

            // 8. 记录安装操作日志
            \App\Models\AdminOperationLog::create([
                'user_id'    => $admin->id,
                'admin_name' => $admin->name,
                'action'     => 'app.created',
                'description' => '通过安装向导完成系统初始化',
                'ip'         => $_SERVER['REMOTE_ADDR'] ?? null,
            ]);

            // 9. 写锁文件
            file_put_contents(LOCK_FILE, '安装时间：' . date('Y-m-d H:i:s') . PHP_EOL);
            $installLog[] = 'install.lock 已生成';

            // 10. 缓存配置与路由（生产优化）
            @unlink(BASE_PATH . '/bootstrap/cache/routes-v7.php');
            $kernel->call('optimize', []);
            $installLog[] = '配置与路由缓存已生成';

            $success = true;
        } catch (Throwable $e) {
            // 把完整异常写入日志，便于排查
            @file_put_contents(
                BASE_PATH . '/storage/logs/install-error.log',
                date('Y-m-d H:i:s') . ' ' . get_class($e) . ': ' . $e->getMessage()
                . ' @ ' . $e->getFile() . ':' . $e->getLine() . PHP_EOL
                . $e->getTraceAsString() . PHP_EOL . PHP_EOL,
                FILE_APPEND
            );

            // 记录已完成到哪一步，便于定位问题
            $msg = $e->getMessage();
            if ($msg === '') {
                // 某些异常（如 PDO 包装异常）消息为空，退回到类名与位置
                $msg = get_class($e) . '（无详细信息）';
            }
            $errors[] = '安装失败：' . $msg
                . ' @ ' . basename((string) $e->getFile()) . ':' . $e->getLine();
            if (!empty($installLog)) {
                $errors[] = '已完成的步骤：' . implode(' → ', $installLog);
            }
        }
    }
}

// ---------------------------------------------------------------------------
//  自动推断站点地址
// ---------------------------------------------------------------------------
$guessUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http')
    . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost')
    . rtrim(dirname((string) ($_SERVER['SCRIPT_NAME'] ?? '/install.php')), '/\\');

// ============================================================================
//  页面渲染
// ============================================================================

renderPage($success ? '安装完成' : '安装向导', function () use (
    $success, $errors, $installLog, $checks, $envOk, $guessUrl
) {
    if ($success):
        ?>
        <div class="alert alert-success">
            <h2>安装成功</h2>
            <p>系统已就绪，可以开始使用了。</p>
        </div>

        <div class="card">
            <h3>已完成的操作</h3>
            <ul class="log">
                <?php foreach ($installLog as $line): ?>
                    <li><?= h($line) ?></li>
                <?php endforeach; ?>
            </ul>
        </div>

        <div class="alert alert-danger">
            <h3>请立即执行以下操作</h3>
            <ol>
                <li><strong>删除本文件 <code>install.php</code></strong> —— 否则他人可重置你的数据库</li>
                <li><strong>备份 <code>.env</code> 文件</strong> —— 其中的 APP_KEY 丢失后，已加密的卡密与密钥将无法恢复</li>
                <li>确认站点根目录指向 <code>public/</code>，并访问 <code>/.env</code> 应返回 404</li>
                <li>配置定时任务：<code>php artisan schedule:run</code> 每分钟执行一次</li>
            </ol>
        </div>

        <div class="actions">
            <a class="btn btn-primary" href="/admin">进入后台管理</a>
        </div>
        <?php
        return;
    endif;
    ?>

    <?php if (!$envOk): ?>
        <div class="alert alert-danger">
            <h3>环境检查未通过</h3>
            <p>请先解决下列问题再继续安装。</p>
        </div>
    <?php endif; ?>

    <div class="card">
        <h3>环境检查</h3>
        <table class="table">
            <thead>
                <tr><th>项目</th><th>当前值</th><th>要求</th><th>状态</th></tr>
            </thead>
            <tbody>
            <?php foreach ($checks as $c): ?>
                <tr>
                    <td><?= h($c['name']) ?></td>
                    <td class="mono"><?= h($c['current']) ?></td>
                    <td class="mono"><?= h($c['required']) ?></td>
                    <td>
                        <?php if ($c['ok']): ?>
                            <span class="badge ok">通过</span>
                        <?php else: ?>
                            <span class="badge fail">不满足</span>
                        <?php endif; ?>
                        <?php if (!empty($c['note'])): ?>
                            <small class="muted"><?= h($c['note']) ?></small>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <?php if (!empty($errors)): ?>
        <div class="alert alert-danger">
            <h3>安装未完成</h3>
            <ul>
                <?php foreach ($errors as $e): ?>
                    <li><?= h($e) ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <form method="post" autocomplete="off">
        <div class="card">
            <h3>数据库配置</h3>
            <p class="muted">本系统使用 MySQL / MariaDB。数据库不存在时会自动创建。</p>
            <div class="grid">
                <label>
                    <span>数据库地址</span>
                    <input type="text" name="db_host" value="<?= h($_POST['db_host'] ?? '127.0.0.1') ?>" required>
                </label>
                <label>
                    <span>端口</span>
                    <input type="text" name="db_port" value="<?= h($_POST['db_port'] ?? '3306') ?>" required>
                </label>
                <label>
                    <span>数据库名</span>
                    <input type="text" name="db_name" value="<?= h($_POST['db_name'] ?? 'cardkey') ?>" required>
                </label>
                <label>
                    <span>用户名</span>
                    <input type="text" name="db_user" value="<?= h($_POST['db_user'] ?? 'root') ?>" required>
                </label>
                <label class="full">
                    <span>密码</span>
                    <input type="password" name="db_pass" value="">
                    <small>若数据库无密码请留空</small>
                </label>
            </div>
        </div>

        <div class="card">
            <h3>管理员账号</h3>
            <p class="muted">用于登录后台管理系统。</p>
            <div class="grid">
                <label>
                    <span>用户名</span>
                    <input type="text" name="admin_name" value="<?= h($_POST['admin_name'] ?? '管理员') ?>" required>
                </label>
                <label>
                    <span>邮箱（登录账号）</span>
                    <input type="email" name="admin_email" value="<?= h($_POST['admin_email'] ?? '') ?>" required>
                </label>
                <label>
                    <span>密码</span>
                    <input type="password" name="admin_pass" required minlength="8">
                    <small>至少 8 位，建议 12 位以上并混合大小写与数字</small>
                </label>
                <label>
                    <span>确认密码</span>
                    <input type="password" name="admin_pass2" required minlength="8">
                </label>
            </div>
        </div>

        <div class="card">
            <h3>站点信息</h3>
            <div class="grid">
                <label class="full">
                    <span>站点地址</span>
                    <input type="text" name="app_url" value="<?= h($_POST['app_url'] ?? $guessUrl) ?>" required>
                    <small>用于生成后台链接，例如 https://card.example.com</small>
                </label>
                <label>
                    <span>站点名称</span>
                    <input type="text" name="app_name" value="<?= h($_POST['app_name'] ?? '卡密管理系统') ?>">
                </label>
                <label>
                    <span>后台品牌名称</span>
                    <input type="text" name="brand_name" value="<?= h($_POST['brand_name'] ?? '卡密管理系统') ?>">
                    <small>显示在后台左上角</small>
                </label>
                <label class="full">
                    <span>备份加密密码（可选）</span>
                    <input type="password" name="backup_pass" value="">
                    <small>用于加密自动备份文件。留空则备份任务会跳过，建议填写</small>
                </label>
            </div>
        </div>

        <div class="actions">
            <button type="submit" class="btn btn-primary" <?= $envOk ? '' : 'disabled' ?>>
                开始安装
            </button>
        </div>
    </form>
    <?php
});

// ============================================================================
//  函数
// ============================================================================

/**
 * 判断目录是否真的可写 —— 实际创建并删除临时文件。
 *
 * Windows 上 is_writable() 对目录的判断经常与实际情况不符，
 * 因此用真实写入来验证。
 */
function canWriteTo(string $dir): bool
{
    if (!is_dir($dir)) {
        return false;
    }

    $probe = rtrim($dir, '/\\') . DIRECTORY_SEPARATOR . '.write_probe_' . bin2hex(random_bytes(4));

    // 用 @ 抑制警告，失败时返回 false
    if (@file_put_contents($probe, 'ok') === false) {
        return false;
    }

    @unlink($probe);
    return true;
}

/**
 * 环境检查。
 */
function runEnvironmentChecks(): array
{
    $checks = [];

    // PHP 版本
    $checks[] = [
        'name'     => 'PHP 版本',
        'current'  => PHP_VERSION,
        'required' => '>= ' . MIN_PHP,
        'ok'       => version_compare(PHP_VERSION, MIN_PHP, '>='),
    ];

    // 必需扩展
    $extensions = [
        'pdo_mysql' => 'MySQL 数据库驱动',
        'mbstring'  => '多字节字符串处理',
        'openssl'   => '加密与签名',
        'fileinfo'  => '文件类型检测',
        'ctype'     => '字符类型检测',
        'json'      => 'JSON 处理',
        'bcmath'    => '高精度计算',
        'tokenizer' => '模板解析',
        'xml'       => 'XML 处理',
        'zip'       => 'Excel 导出',
        'curl'      => 'HTTP 请求',
    ];
    foreach ($extensions as $ext => $desc) {
        $checks[] = [
            'name'     => "扩展 {$ext}",
            'current'  => extension_loaded($ext) ? '已安装' : '未安装',
            'required' => $desc,
            'ok'       => extension_loaded($ext),
        ];
    }

    // 可选扩展 —— 缺失不阻塞安装，但会影响部分功能
    $optional = [
        'gd'    => 'Excel 导出（插入图片时）',
        'intl'  => '国际化格式化',
        'exif'  => '图片元数据',
    ];
    foreach ($optional as $ext => $desc) {
        $loaded = extension_loaded($ext);
        $checks[] = [
            'name'     => "扩展 {$ext}（可选）",
            'current'  => $loaded ? '已安装' : '未安装',
            'required' => $desc,
            'ok'       => true,   // 不阻塞安装
            'note'     => $loaded ? '' : '缺失不影响使用，仅个别功能受限',
        ];
    }

    // 目录可写
    //
    // 注意：Windows 上 is_writable() 对目录的判断不可靠
    // （ACL 与 POSIX 权限模型不同，内置服务器进程可能误判）。
    // 因此这里实际写入一个临时文件来验证，这比 is_writable 更准确。
    $dirs = [
        '根目录（写入 .env）'  => BASE_PATH,
        'storage（存储）'      => BASE_PATH . '/storage',
        'bootstrap/cache'     => BASE_PATH . '/bootstrap/cache',
    ];
    foreach ($dirs as $name => $path) {
        $writable = canWriteTo($path);
        $checks[] = [
            'name'     => "可写：{$name}",
            'current'  => $writable ? '可写' : '不可写',
            'required' => '需要写入权限',
            'ok'       => $writable,
        ];
    }

    // vendor 目录
    $checks[] = [
        'name'     => 'Composer 依赖',
        'current'  => is_dir(BASE_PATH . '/vendor') ? '已安装' : '缺失',
        'required' => '需执行 composer install',
        'ok'       => is_file(BASE_PATH . '/vendor/autoload.php'),
    ];

    // 前端资源
    $checks[] = [
        'name'     => '前端资源',
        'current'  => is_file(BASE_PATH . '/public/build/manifest.json') ? '已构建' : '缺失',
        'required' => '需执行 npm run build',
        'ok'       => is_file(BASE_PATH . '/public/build/manifest.json'),
    ];

    return $checks;
}

/**
 * 写入 .env 文件。
 *
 * 以 .env.example 为模板，替换掉数据库与管理相关的值。
 */
function writeEnvFile(array $input): void
{
    $template = is_file(ENV_EXAMPLE)
        ? (string) file_get_contents(ENV_EXAMPLE)
        : defaultEnvTemplate();

    $replacements = [
        'APP_NAME'     => '"' . $input['app_name'] . '"',
        'APP_ENV'      => 'production',
        'APP_DEBUG'    => 'false',
        'APP_URL'      => $input['app_url'],
        'DB_CONNECTION' => 'mysql',
        'DB_HOST'      => $input['db_host'],
        'DB_PORT'      => $input['db_port'],
        'DB_DATABASE'  => $input['db_name'],
        'DB_USERNAME'  => $input['db_user'],
        'DB_PASSWORD'  => quoteEnv($input['db_pass']),
        'SESSION_DRIVER'   => 'file',
        // 显式指定 cookie 名：中文 APP_NAME 经 Str::slug() 会变空串，
        // 导致 cookie 名退化为 "-session"，部分环境下会话无法保持
        'SESSION_COOKIE'   => 'cardkey_session',
        'CACHE_STORE'      => 'database',
        'QUEUE_CONNECTION' => 'database',
        'BACKUP_ENCRYPTION_PASSWORD' => quoteEnv($input['backup_pass']),
    ];

    foreach ($replacements as $key => $value) {
        $template = setEnvLine($template, $key, $value);
    }

    // 移除残留的 sqlite 配置（若模板里有）
    $template = removeEnvLine($template, 'DB_FOREIGN_KEYS');

    if (file_put_contents(ENV_FILE, $template) === false) {
        throw new RuntimeException('无法写入 .env 文件，请检查目录权限');
    }
}

/**
 * 更新 .env 中的单个值。
 */
function updateEnvValue(string $key, string $value): void
{
    if (!is_file(ENV_FILE)) {
        throw new RuntimeException('.env 不存在');
    }
    $content = (string) file_get_contents(ENV_FILE);
    $content = setEnvLine($content, $key, $value);

    if (file_put_contents(ENV_FILE, $content) === false) {
        throw new RuntimeException("无法写入 {$key}");
    }
}

/**
 * 在 env 内容中设置一行键值。存在则替换，不存在则追加。
 */
function setEnvLine(string $content, string $key, string $value): string
{
    $pattern = '/^' . preg_quote($key, '/') . '=.*$/m';

    if (preg_match($pattern, $content)) {
        return (string) preg_replace($pattern, $key . '=' . $value, $content);
    }

    return rtrim($content, "\n") . "\n" . $key . '=' . $value . "\n";
}

/**
 * 移除 env 中的一行。
 */
function removeEnvLine(string $content, string $key): string
{
    return (string) preg_replace('/^' . preg_quote($key, '/') . '=.*\n?/m', '', $content);
}

/**
 * 需要引号包裹的 env 值。
 */
function quoteEnv(string $value): string
{
    if ($value === '') {
        return '';
    }
    return '"' . str_replace('"', '\"', $value) . '"';
}

/**
 * .env.example 缺失时的兜底模板。
 */
function defaultEnvTemplate(): string
{
    return <<<'ENV'
APP_NAME="卡密管理系统"
APP_ENV=production
APP_KEY=
APP_DEBUG=false
APP_URL=http://localhost
APP_LOCALE=zh_CN
APP_FALLBACK_LOCALE=en
APP_FAKER_LOCALE=zh_CN

LOG_CHANNEL=stack
LOG_STACK=single
LOG_LEVEL=warning

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=cardkey
DB_USERNAME=root
DB_PASSWORD=

SESSION_DRIVER=file
SESSION_LIFETIME=120
SESSION_ENCRYPT=false
SESSION_PATH=/
SESSION_DOMAIN=null

CACHE_STORE=database
QUEUE_CONNECTION=database

BACKUP_ENCRYPTION_PASSWORD=
ENV;
}

/**
 * HTML 转义。
 */
function h(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

/**
 * 渲染页面。
 */
function renderPage(string $title, callable $body): void
{
    ?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= h($title) ?> - 卡密系统</title>
    <style>
        :root {
            --bg: #f6f7f9;
            --card: #ffffff;
            --border: #e3e5e8;
            --text: #1f2329;
            --muted: #8a9099;
            --primary: #4f46e5;
            --success: #16a34a;
            --danger: #dc2626;
            --warning: #d97706;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            padding: 32px 16px 64px;
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif;
            font-size: 14px;
            line-height: 1.6;
        }
        .wrap { max-width: 860px; margin: 0 auto; }
        h1 { font-size: 22px; margin: 0 0 4px; font-weight: 600; }
        h2 { font-size: 18px; margin: 0 0 8px; font-weight: 600; }
        h3 { font-size: 15px; margin: 0 0 12px; font-weight: 600; }
        .sub { color: var(--muted); margin: 0 0 24px; }
        .card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 16px;
        }
        .alert {
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 16px;
            border: 1px solid;
        }
        .alert ul, .alert ol { margin: 8px 0 0; padding-left: 20px; }
        .alert li { margin-bottom: 4px; }
        .alert-success { background: #f0fdf4; border-color: #bbf7d0; color: #14532d; }
        .alert-danger  { background: #fef2f2; border-color: #fecaca; color: #7f1d1d; }
        .alert-warning { background: #fffbeb; border-color: #fde68a; color: #78350f; }
        .table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .table th, .table td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
        .table th { font-weight: 600; color: var(--muted); font-size: 12px; text-transform: uppercase; }
        .table tr:last-child td { border-bottom: none; }
        .mono { font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; }
        .badge.ok { background: #dcfce7; color: #166534; }
        .badge.fail { background: #fee2e2; color: #991b1b; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
        .grid label.full { grid-column: 1 / -1; }
        label { display: block; }
        label > span { display: block; font-weight: 500; margin-bottom: 6px; font-size: 13px; }
        label small { display: block; color: var(--muted); font-size: 12px; margin-top: 4px; }
        input[type=text], input[type=password], input[type=email] {
            width: 100%;
            padding: 9px 12px;
            border: 1px solid var(--border);
            border-radius: 6px;
            font-size: 14px;
            font-family: inherit;
            background: #fff;
        }
        input:focus { outline: 2px solid var(--primary); outline-offset: -1px; border-color: var(--primary); }
        .actions { margin-top: 24px; }
        .btn {
            display: inline-block;
            padding: 10px 20px;
            border-radius: 6px;
            border: 1px solid var(--border);
            background: #fff;
            color: var(--text);
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            text-decoration: none;
        }
        .btn-primary { background: var(--primary); border-color: var(--primary); color: #fff; }
        .btn-primary:disabled { opacity: .5; cursor: not-allowed; }
        .log { margin: 0; padding-left: 20px; }
        .log li { margin-bottom: 4px; }
        code { background: #f1f2f4; padding: 1px 6px; border-radius: 4px; font-size: 12px; font-family: ui-monospace, Consolas, monospace; }
        .muted { color: var(--muted); }
        @media (max-width: 640px) { .grid { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
<div class="wrap">
    <h1><?= h($title) ?></h1>
    <p class="sub">卡密系统 · 安装向导</p>
    <?php $body(); ?>
</div>
</body>
</html>
    <?php
}
