<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * 管理员操作日志（追加写）。
 */
class AdminOperationLog extends Model
{
    public const UPDATED_AT = null;

    protected $fillable = [
        'user_id',
        'admin_name',
        'action',
        'description',
        'target_type',
        'target_id',
        'changes',
        'ip',
        'user_agent',
        'created_at',
    ];

    protected function casts(): array
    {
        return [
            'changes' => 'array',
            'created_at' => 'datetime',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * 操作类型的中文名，用于后台筛选。
     */
    public function getActionLabelAttribute(): string
    {
        return match ($this->action) {
            'auth.login' => '登录成功',
            'auth.logout' => '退出登录',
            'auth.login_failed' => '登录失败',
            'auth.locked' => '账号锁定',
            'auth.password_changed' => '修改密码',
            'auth.2fa_enabled' => '启用双因素认证',
            'auth.2fa_disabled' => '关闭双因素认证',
            'app.created' => '创建应用',
            'app.updated' => '修改应用',
            'app.deleted' => '删除应用',
            'app.secret_rotated' => '重置应用密钥',
            'app.secret_viewed' => '查看应用密钥',
            'app.status_toggled' => '切换应用状态',
            'card.batch_generated' => '批量生成卡密',
            'card.imported' => '导入卡密',
            'card.exported' => '导出卡密',
            'card.code_viewed' => '查看卡密明文',
            'card.disabled' => '禁用卡密',
            'card.enabled' => '启用卡密',
            'card.deleted' => '删除卡密',
            'card.extended' => '延长有效期',
            'card.binding_reset' => '重置设备绑定',
            'card.uses_reset' => '重置次数',
            'settings.updated' => '修改系统设置',
            'log.cleaned' => '清理日志',
            'backup.created' => '创建备份',
            default => $this->action,
        };
    }
}
