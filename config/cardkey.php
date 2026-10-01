<?php

return [

    /*
    |--------------------------------------------------------------------------
    | API 签名协议
    |--------------------------------------------------------------------------
    |
    | 这些值定义了跨语言客户端模板必须遵守的协议细节。修改后需同步更新
    | docs/API.md 与所有语言模板。
    |
    */
    'signature' => [
        'version' => 'v1',
        'algorithm' => 'HMAC-SHA256',
        'headers' => [
            'app_id' => 'X-App-Id',
            'timestamp' => 'X-Timestamp',
            'nonce' => 'X-Nonce',
            'signature' => 'X-Signature',
            'version' => 'X-Signature-Version',
        ],
        'response_headers' => [
            'timestamp' => 'X-Response-Timestamp',
            'signature' => 'X-Response-Signature',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | 卡密传输加密
    |--------------------------------------------------------------------------
    */
    'transport' => [
        'info' => 'cardkey-enc-v1',
        'cipher' => 'AES-256-GCM',
    ],

    /*
    |--------------------------------------------------------------------------
    | 可配置项定义
    |--------------------------------------------------------------------------
    |
    | 单一事实来源：SettingsService 从中读取默认值与类型，
    | 后台「系统设置」页面据此自动生成表单。
    |
    | 字段说明：
    |   key      —— 存储键名，形如 group.name
    |   type     —— string / integer / boolean / json
    |   default  —— 默认值
    |   label    —— 后台显示名
    |   help     —— 后台提示文案
    |   secret   —— 是否敏感（后台用密码框展示）
    |
    */
    'settings' => [

        // ---------------- 应用外观 ----------------
        'app.brand_name' => [
            'type' => 'string', 'default' => '卡密管理系统', 'group' => 'app',
            'label' => '左上角品牌名称',
            'help' => '显示在后台左上角和页面标题中。',
        ],

        // ---------------- 日志保留 ----------------
        'log.verification_retention_days' => [
            'type' => 'integer', 'default' => 30, 'group' => 'log',
            'label' => '验证日志保留天数',
            'help' => '超过天数的卡密验证日志会被自动清理任务删除。设为 0 表示永久保留。',
        ],
        'log.operation_retention_days' => [
            'type' => 'integer', 'default' => 90, 'group' => 'log',
            'label' => '操作日志保留天数',
            'help' => '管理员操作日志的保留天数，设为 0 表示永久保留。',
        ],
        'log.login_retention_days' => [
            'type' => 'integer', 'default' => 90, 'group' => 'log',
            'label' => '登录日志保留天数',
            'help' => '管理员登录日志的保留天数，设为 0 表示永久保留。',
        ],
        'log.nonce_retention_hours' => [
            'type' => 'integer', 'default' => 24, 'group' => 'log',
            'label' => '防重放记录保留小时数',
            'help' => '已使用的 nonce 记录保留时长，应大于签名时间戳容忍窗口。',
        ],

        // ---------------- API 安全参数 ----------------
        'api.timestamp_tolerance' => [
            'type' => 'integer', 'default' => 300, 'group' => 'api',
            'label' => '签名时间戳容忍偏移（秒）',
            'help' => '请求时间戳与服务器时间相差超过该值即判定为过期请求。建议 60~300 秒。',
        ],
        'api.nonce_ttl' => [
            'type' => 'integer', 'default' => 600, 'group' => 'api',
            'label' => 'Nonce 有效期（秒）',
            'help' => '同一 nonce 在该时间窗口内不允许重复使用，用于防止重放攻击。',
        ],
        'api.rate_limit_per_minute' => [
            'type' => 'integer', 'default' => 60, 'group' => 'api',
            'label' => '默认每分钟请求上限',
            'help' => '新建应用的默认限流值。每个应用可在应用详情中单独覆盖。',
        ],
        'api.default_daily_quota' => [
            'type' => 'integer', 'default' => 0, 'group' => 'api',
            'label' => '默认每日调用配额',
            'help' => '新建应用的默认每日调用上限。0 表示不限制。',
        ],
        'api.require_encrypted_card' => [
            'type' => 'boolean', 'default' => true, 'group' => 'api',
            'label' => '强制卡密密文传输',
            'help' => '开启后，客户端必须使用 AES-256-GCM 加密卡密后再提交，明文卡密将被拒绝。',
        ],
        'api.response_signature' => [
            'type' => 'boolean', 'default' => true, 'group' => 'api',
            'label' => '响应体附带签名',
            'help' => '开启后，服务端会在响应头返回 X-Response-Signature，客户端可校验返回值未被篡改。',
        ],
        'api.trusted_proxies' => [
            'type' => 'string', 'default' => '', 'group' => 'api',
            'label' => '可信反向代理',
            'help' => '部署在 Nginx/CDN 之后时填写，如 127.0.0.1 或 *。用于正确识别客户端真实 IP，留空表示不信任任何代理。',
        ],

        // ---------------- 后台登录安全 ----------------
        'security.force_https' => [
            'type' => 'boolean', 'default' => false, 'group' => 'security',
            'label' => '强制 HTTPS 访问',
            'help' => '生产环境务必开启。开启后所有 http 请求将被重定向到 https。本地调试时可关闭。',
        ],
        'security.session_idle_minutes' => [
            'type' => 'integer', 'default' => 30, 'group' => 'security',
            'label' => '会话空闲超时（分钟）',
            'help' => '管理员在该时间内无操作则自动退出登录。设为 0 表示不启用空闲超时。',
        ],
        'security.max_login_attempts' => [
            'type' => 'integer', 'default' => 5, 'group' => 'security',
            'label' => '登录失败次数上限',
            'help' => '连续失败达到该次数后临时锁定账号。',
        ],
        'security.lockout_minutes' => [
            'type' => 'integer', 'default' => 15, 'group' => 'security',
            'label' => '账号锁定时长（分钟）',
            'help' => '触发失败上限后账号被锁定的时长。',
        ],
        'security.password_min_length' => [
            'type' => 'integer', 'default' => 12, 'group' => 'security',
            'label' => '密码最小长度',
            'help' => '强密码策略要求的最小长度，建议不低于 12。',
        ],
        'security.password_expiry_days' => [
            'type' => 'integer', 'default' => 0, 'group' => 'security',
            'label' => '密码有效期（天）',
            'help' => '超过该天数后强制修改密码。设为 0 表示不强制。',
        ],
        'security.require_2fa' => [
            'type' => 'boolean', 'default' => false, 'group' => 'security',
            'label' => '强制启用双因素认证',
            'help' => '开启后，未配置 2FA 的管理员登录后必须完成绑定才能进入后台。',
        ],

        // ---------------- 卡密策略 ----------------
        'card.default_max_devices' => [
            'type' => 'integer', 'default' => 1, 'group' => 'card',
            'label' => '默认可绑定设备数',
            'help' => '新建卡密默认允许绑定的设备数量，1 表示单设备绑定。',
        ],
        'card.expiring_soon_days' => [
            'type' => 'integer', 'default' => 7, 'group' => 'card',
            'label' => '即将过期提醒天数',
            'help' => '距离到期不足该天数的卡密会在仪表盘提醒。',
        ],
        'card.auto_disable_expired' => [
            'type' => 'boolean', 'default' => false, 'group' => 'card',
            'label' => '自动禁用过期卡密',
            'help' => '开启后，定时任务会把过期卡密状态置为「已过期」并可选禁用。',
        ],

        // ---------------- 备份 ----------------
        'backup.enabled' => [
            'type' => 'boolean', 'default' => true, 'group' => 'backup',
            'label' => '启用自动备份',
            'help' => '开启后，定时任务会加密备份数据库。',
        ],
        'backup.retention_days' => [
            'type' => 'integer', 'default' => 7, 'group' => 'backup',
            'label' => '备份保留天数',
            'help' => '超过天数的备份文件会被自动删除。',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | 卡密生成参数
    |--------------------------------------------------------------------------
    */
    'card' => [
        'groups' => 4,
        'group_size' => 4,
        'charset' => '23456789ABCDEFGHJKMNPQRSTUVWXYZ',
        'max_batch_size' => 10000,
    ],

    /*
    |--------------------------------------------------------------------------
    | 备份
    |--------------------------------------------------------------------------
    */
    'backup' => [
        'disk' => 'local',
        'path' => 'backups',
        // 备份文件使用该密码加密（openssl aes-256-cbc + PBKDF2）。
        // 请务必修改并通过环境变量注入，切勿使用默认值。
        'password' => env('BACKUP_ENCRYPTION_PASSWORD', ''),

        // mysqldump 可执行文件路径。
        // 留空则自动探测常见位置（含宝塔的 /www/server/mysql*/bin/）。
        // 若自动探测失败，在此填写完整路径，例如 /www/server/mysql/bin/mysqldump
        'mysqldump' => env('BACKUP_MYSQLDUMP_PATH', ''),
    ],

];
