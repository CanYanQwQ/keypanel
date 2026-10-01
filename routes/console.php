<?php

use App\Enums\CardStatus;
use App\Models\ApiNonce;
use App\Models\CardKey;
use App\Models\LoginLog;
use App\Models\VerificationLog;
use App\Models\AdminOperationLog;
use App\Services\SettingsService;
use Carbon\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schedule;
use Illuminate\Support\Facades\Storage;

// =========================================================================
// 定时清理：日志、nonce、卡密状态
// =========================================================================
Schedule::command('cardkey:clean-logs')->dailyAt('03:00')->withoutOverlapping();
Schedule::command('cardkey:clean-nonces')->everyThirtyMinutes()->withoutOverlapping();
Schedule::command('cardkey:sync-card-status')->everyFifteenMinutes()->withoutOverlapping();

// =========================================================================
// 备份（需要 BACKUP_ENCRYPTION_PASSWORD 环境变量）
// =========================================================================
Schedule::command('cardkey:backup')->dailyAt('04:00')->withoutOverlapping()
    ->when(fn () => SettingsService::getBool('backup.enabled'));

// =========================================================================
// cardkey:clean-logs
// =========================================================================
Artisan::command('cardkey:clean-logs', function () {
    $vr = SettingsService::getInt('log.verification_retention_days');
    $op = SettingsService::getInt('log.operation_retention_days');
    $lg = SettingsService::getInt('log.login_retention_days');

    $counts = [];

    if ($vr > 0) {
        $counts['verification'] = VerificationLog::where('created_at', '<', now()->subDays($vr))->delete();
    }

    if ($op > 0) {
        $counts['operation'] = AdminOperationLog::where('created_at', '<', now()->subDays($op))->delete();
    }

    if ($lg > 0) {
        $counts['login'] = LoginLog::where('created_at', '<', now()->subDays($lg))->delete();
    }

    $total = array_sum($counts);
    $this->info("日志清理完成：共删除 {$total} 条");
})->purpose('按保留策略清理过期日志');

// =========================================================================
// cardkey:clean-nonces
// =========================================================================
Artisan::command('cardkey:clean-nonces', function () {
    $count = ApiNonce::where('expires_at', '<', now())->delete();
    $this->info("已清理 {$count} 条过期 nonce 记录");
})->purpose('清理已过期的防重放 nonce 记录');

// =========================================================================
// cardkey:sync-card-status
// =========================================================================
Artisan::command('cardkey:sync-card-status', function () {
    // 到期卡
    $expired = CardKey::whereIn('status', [CardStatus::Unused->value, CardStatus::Activated->value])
        ->whereNotNull('expires_at')
        ->where('expires_at', '<', now())
        ->update([
            'status' => CardStatus::Expired->value,
            'updated_at' => now(),
        ]);

    // 次数用完
    $depleted = CardKey::whereIn('status', [CardStatus::Unused->value, CardStatus::Activated->value])
        ->where('type', 'count')
        ->whereColumn('used_count', '>=', 'max_uses')
        ->update([
            'status' => CardStatus::Depleted->value,
            'updated_at' => now(),
        ]);

    $this->info("已同步卡密状态：{$expired} 张到期，{$depleted} 张用完");
})->purpose('同步卡密自动到期/用完状态');

// =========================================================================
// cardkey:backup
// =========================================================================
Artisan::command('cardkey:backup', function () {
    $disk = config('cardkey.backup.disk', 'local');
    $path = config('cardkey.backup.path', 'backups');
    $password = (string) config('cardkey.backup.password', '');

    if ($password === '') {
        $this->warn('未配置 BACKUP_ENCRYPTION_PASSWORD，跳过加密备份');

        return;
    }

    // ---- 读取数据库连接信息 ----
    $connection = config('database.default');
    $config = config("database.connections.{$connection}", []);

    if (($config['driver'] ?? '') !== 'mysql') {
        $this->error("暂不支持的数据库驱动：{$config['driver']}（仅支持 mysql）");

        return;
    }

    $host = $config['host'] ?? '127.0.0.1';
    $port = (int) ($config['port'] ?? 3306);
    $database = $config['database'] ?? '';
    $username = $config['username'] ?? '';
    $dbPassword = (string) ($config['password'] ?? '');

    if ($database === '') {
        $this->error('数据库名称为空，无法备份');

        return;
    }

    // ---- 定位 mysqldump ----
    // 宝塔的 mysqldump 通常不在 PATH 中，需要按常见路径查找
    $dumpBinary = findMysqldumpBinary();

    if ($dumpBinary === null) {
        $this->error('未找到 mysqldump 命令。请确认 MySQL 客户端已安装，'
            . '或在 config/cardkey.php 中通过 backup.mysqldump 指定完整路径。');

        return;
    }

    $timestamp = now()->format('Ymd_His');
    $filename = "cardkey_backup_{$timestamp}.sql.enc";
    $tmpSql = storage_path("app/cardkey_backup_{$timestamp}.sql");
    $tmpEnc = storage_path("app/{$filename}");

    // ---- 导出 ----
    //
    // 密码通过 MYSQL_PWD 环境变量传递，不写在命令行里。
    // 原因：命令行参数在服务器上可被同机其他用户通过 ps 看到，
    // 而环境变量只在当前进程可见，泄露风险低得多。
    //
    // 注意：`VAR=value command` 是 POSIX shell 语法，Windows 的 cmd 不支持。
    // 生产环境（宝塔 / Linux）走前者；Windows 下退回把密码写进参数（仅本地调试）。
    $isWindows = DIRECTORY_SEPARATOR === '\\';

    $baseArgs = sprintf(
        '--host=%s --port=%d --user=%s '
        . '--single-transaction --quick --skip-lock-tables --routines --events '
        . '--default-character-set=utf8mb4 %s',
        escapeshellarg($host),
        $port,
        escapeshellarg($username),
        escapeshellarg($database),
    );

    if ($isWindows) {
        // Windows cmd 对 `> file 2>&1` 的解析不稳定，这里只重定向 stdout，
        // stderr 交给 exec 的第二参数捕获。
        $cmd = sprintf(
            '%s %s --password=%s > %s',
            escapeshellarg($dumpBinary),
            $baseArgs,
            escapeshellarg($dbPassword),
            escapeshellarg($tmpSql),
        );
    } else {
        $cmd = sprintf(
            'MYSQL_PWD=%s %s %s > %s 2>&1',
            escapeshellarg($dbPassword),
            escapeshellarg($dumpBinary),
            $baseArgs,
            escapeshellarg($tmpSql),
        );
    }

    $output = [];
    $exitCode = 0;
    exec($cmd, $output, $exitCode);

    // 判断依据是退出码与产物文件，而不是输出是否为空 ——
    // 某些环境下 shell 会把启动横幅写入输出，导致误判。
    if ($exitCode !== 0 || ! is_file($tmpSql) || filesize($tmpSql) === 0) {
        @unlink($tmpSql);
        $this->error('数据库导出失败：' . implode("
", $output));

        return;
    }

    $this->info('数据库导出完成（' . formatBytes(filesize($tmpSql)) . '）');

    // ---- 加密 ----
    // 同样优先用环境变量传密码，避免出现在进程列表
    $openssl = $isWindows ? 'openssl.exe' : 'openssl';

    if ($isWindows) {
        $encCmd = sprintf(
            '%s enc -aes-256-cbc -pbkdf2 -iter 100000 -salt '
            . '-in %s -out %s -pass pass:%s',
            $openssl,
            escapeshellarg($tmpSql),
            escapeshellarg($tmpEnc),
            escapeshellarg($password),
        );
    } else {
        $encCmd = sprintf(
            'OPENSSL_PASS=%s %s enc -aes-256-cbc -pbkdf2 -iter 100000 -salt '
            . '-in %s -out %s -pass env:OPENSSL_PASS 2>&1',
            escapeshellarg($password),
            $openssl,
            escapeshellarg($tmpSql),
            escapeshellarg($tmpEnc),
        );
    }

    $encOutput = [];
    $encExit = 0;
    exec($encCmd, $encOutput, $encExit);

    @unlink($tmpSql);

    // 同样只看退出码与产物文件，忽略 shell 的额外输出
    if ($encExit !== 0 || ! is_file($tmpEnc) || filesize($tmpEnc) === 0) {
        @unlink($tmpEnc);
        $this->error('备份加密失败：' . implode("
", $encOutput));

        return;
    }

    // ---- 清理过期备份 ----
    $retention = SettingsService::getInt('backup.retention_days', 7);

    if ($retention > 0) {
        foreach (Storage::disk($disk)->files($path) as $file) {
            $lastModified = Storage::disk($disk)->lastModified($file);

            if ($lastModified !== null && $lastModified < now()->subDays($retention)->timestamp) {
                Storage::disk($disk)->delete($file);
            }
        }
    }

    // ---- 归档 ----
    Storage::disk($disk)->putFileAs($path, new \Illuminate\Http\File($tmpEnc), $filename);
    @unlink($tmpEnc);

    $this->info("备份创建成功：{$filename}");
})->purpose('加密备份数据库（mysqldump + AES-256-CBC）');


/**
 * 查找 mysqldump 可执行文件。
 *
 * 宝塔面板安装的 MySQL 不会把 mysqldump 加入 PATH，
 * 因此按常见安装位置依次探测。
 *
 * 用 function_exists 守卫的原因：Laravel 在执行 optimize / config:cache 等命令时
 * 可能重复加载本文件，裸函数声明会触发 "Cannot redeclare" 致命错误。
 */
if (! function_exists('findMysqldumpBinary')) {
    function findMysqldumpBinary(): ?string
    {
        // 优先使用配置中显式指定的路径
        $configured = config('cardkey.backup.mysqldump');

        if (is_string($configured) && $configured !== '' && is_executable($configured)) {
            return $configured;
        }

        $candidates = [
            '/usr/bin/mysqldump',
            '/usr/local/bin/mysqldump',
            '/usr/local/mysql/bin/mysqldump',
            '/www/server/mysql/bin/mysqldump',
            '/www/server/mariadb/bin/mysqldump',
        ];

        // 宝塔的 MySQL 可能带版本号目录，例如 /www/server/mysql-5.7/bin/
        foreach (glob('/www/server/mysql*/bin/mysqldump') ?: [] as $found) {
            $candidates[] = $found;
        }
        foreach (glob('/www/server/mariadb*/bin/mysqldump') ?: [] as $found) {
            $candidates[] = $found;
        }

        foreach ($candidates as $candidate) {
            if (is_file($candidate) && is_executable($candidate)) {
                return $candidate;
            }
        }

        // 最后尝试 PATH 中的命令
        $which = @shell_exec('command -v mysqldump 2>/dev/null');

        if (is_string($which) && trim($which) !== '') {
            return trim($which);
        }

        return null;
    }
}

/**
 * 把字节数格式化为可读文本。
 */
if (! function_exists('formatBytes')) {
    function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $index = 0;
        $value = (float) $bytes;

        while ($value >= 1024 && $index < count($units) - 1) {
            $value /= 1024;
            $index++;
        }

        return round($value, $index === 0 ? 0 : 1) . ' ' . $units[$index];
    }
}
