<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('apps', function (Blueprint $table) {
            $table->id();

            $table->string('name');
            $table->string('app_id', 64)->unique()->comment('公开的应用标识，用于 API 认证');
            $table->text('app_secret_encrypted')->comment('AppSecret 密文（AES-256-GCM），验签时解密使用');
            $table->string('secret_prefix', 24)->comment('密钥前缀，后台列表展示用，如 ak_live_7f3a');
            $table->timestamp('secret_rotated_at')->nullable();

            $table->string('status', 16)->default('enabled')->index();
            $table->text('description')->nullable();

            // API 安全参数（每应用可独立配置）
            $table->json('ip_whitelist')->nullable()->comment('IP 白名单，支持单个 IP 与 CIDR，空=不限制');
            $table->unsignedInteger('rate_limit_per_minute')->default(60)->comment('每分钟最大请求数');
            $table->unsignedInteger('daily_quota')->nullable()->comment('每日调用上限，null=不限');
            $table->unsignedInteger('timestamp_tolerance')->default(300)->comment('签名时间戳容忍偏移（秒）');
            $table->boolean('require_encrypted_card')->default(true)->comment('是否强制卡密密文传输');

            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();

            $table->index(['status', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('apps');
    }
};
