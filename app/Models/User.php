<?php

namespace App\Models;

use App\Services\SettingsService;
use Database\Factories\UserFactory;
use Filament\Auth\MultiFactor\App\Concerns\InteractsWithAppAuthentication;
use Filament\Auth\MultiFactor\App\Concerns\InteractsWithAppAuthenticationRecovery;
use Filament\Auth\MultiFactor\App\Contracts\HasAppAuthentication;
use Filament\Auth\MultiFactor\App\Contracts\HasAppAuthenticationRecovery;
use Filament\Models\Contracts\FilamentUser;
use Filament\Panel;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

/**
 * 系统唯一管理员。
 *
 * 安全相关字段：
 *   - failed_login_attempts / locked_until ：登录失败次数与临时锁定
 *   - must_change_password / password_changed_at ：密码策略
 *   - app_authentication_secret / _recovery_codes ：Filament 原生 TOTP 2FA（加密存储）
 */
class User extends Authenticatable implements FilamentUser, HasAppAuthentication, HasAppAuthenticationRecovery
{
    /** @use HasFactory<UserFactory> */
    use HasFactory, Notifiable;
    use InteractsWithAppAuthentication, InteractsWithAppAuthenticationRecovery;

    protected $fillable = [
        'name',
        'email',
        'password',
        'last_login_at',
        'last_login_ip',
        'failed_login_attempts',
        'locked_until',
        'must_change_password',
        'password_changed_at',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
            'last_login_at' => 'datetime',
            'locked_until' => 'datetime',
            'password_changed_at' => 'datetime',
            'failed_login_attempts' => 'integer',
            'must_change_password' => 'boolean',
        ];
    }

    // ------------------------------------------------------------------
    // 面板访问（单管理员：唯一账号即可访问）
    // ------------------------------------------------------------------

    public function canAccessPanel(Panel $panel): bool
    {
        return true;
    }

    // ------------------------------------------------------------------
    // 登录锁定
    // ------------------------------------------------------------------

    public function isLocked(): bool
    {
        return $this->locked_until !== null && $this->locked_until->isFuture();
    }

    public function lockoutRemainingSeconds(): int
    {
        if (! $this->isLocked()) {
            return 0;
        }

        return max(0, (int) now()->diffInSeconds($this->locked_until, false));
    }

    /**
     * 记录一次登录失败，达到上限后锁定账号。返回是否刚触发锁定。
     */
    public function recordFailedLogin(): bool
    {
        $maxAttempts = SettingsService::getInt('security.max_login_attempts');
        $lockoutMinutes = SettingsService::getInt('security.lockout_minutes');

        $this->failed_login_attempts = $this->failed_login_attempts + 1;

        if ($maxAttempts > 0 && $this->failed_login_attempts >= $maxAttempts) {
            $this->locked_until = now()->addMinutes(max(1, $lockoutMinutes));

            // 锁定时重置计数，解锁后重新计数
            $this->failed_login_attempts = 0;
            $this->save();

            return true;
        }

        $this->save();

        return false;
    }

    public function resetFailedLogins(): void
    {
        $this->failed_login_attempts = 0;
        $this->locked_until = null;
        $this->save();
    }

    public function recordSuccessfulLogin(?string $ip): void
    {
        $this->last_login_at = now();
        $this->last_login_ip = $ip;
        $this->failed_login_attempts = 0;
        $this->locked_until = null;
        $this->save();
    }

    /**
     * 密码是否已过期（需强制修改）。
     */
    public function isPasswordExpired(): bool
    {
        $expiryDays = SettingsService::getInt('security.password_expiry_days');

        if ($expiryDays <= 0 || $this->password_changed_at === null) {
            return false;
        }

        return $this->password_changed_at->addDays($expiryDays)->isPast();
    }

    /**
     * 是否已启用 TOTP 双因素认证。
     */
    public function hasTwoFactorEnabled(): bool
    {
        return filled($this->getAppAuthenticationSecret());
    }

    // ------------------------------------------------------------------
    // 关联
    // ------------------------------------------------------------------

    public function loginLogs(): HasMany
    {
        return $this->hasMany(LoginLog::class);
    }

    public function operationLogs(): HasMany
    {
        return $this->hasMany(AdminOperationLog::class);
    }
}
