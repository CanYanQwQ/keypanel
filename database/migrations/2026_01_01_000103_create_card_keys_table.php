<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('card_keys', function (Blueprint $table) {
            $table->id();

            $table->foreignId('app_id')->nullable()->constrained('apps')->nullOnDelete()
                ->comment('所属应用，null 表示通用卡密（所有应用可用）');
            $table->foreignId('batch_id')->nullable()->constrained('card_key_batches')->nullOnDelete();

            // ---- 卡密存储：哈希用于检索，密文用于后台查看/导出 ----
            $table->string('code_hash', 64)->unique()->comment('SHA-256(code)，用于 O(1) 检索，不可逆');
            $table->text('code_encrypted')->comment('卡密密文（AES-256-GCM），供后台反复查看与导出');
            $table->string('code_masked', 40)->comment('掩码，如 ABCD-****-****-WXYZ，日志与列表展示');
            $table->string('code_prefix', 16)->nullable()->index()->comment('明文前缀，用于搜索');

            // ---- 类型与状态 ----
            $table->string('type', 16)->index();
            $table->string('status', 16)->default('unused')->index();

            // ---- 权益参数 ----
            $table->unsignedInteger('duration_value')->nullable()->comment('时间卡/试用卡：激活后的有效时长数值');
            $table->string('duration_unit', 8)->nullable()->comment('时长单位：minute/hour/day/month');
            $table->unsignedInteger('max_uses')->nullable()->comment('次数卡：总可用次数');
            $table->unsignedInteger('used_count')->default(0)->comment('已扣减次数');

            // ---- 生命周期 ----
            $table->timestamp('activated_at')->nullable();
            $table->timestamp('expires_at')->nullable()->index()->comment('到期时间，null=永久');

            // ---- 设备绑定 ----
            $table->string('device_id', 191)->nullable()->index()->comment('已绑定设备指纹');
            $table->timestamp('device_bound_at')->nullable();
            $table->unsignedInteger('bind_count')->default(0)->comment('累计绑定次数');
            $table->unsignedInteger('max_devices')->default(1)->comment('允许绑定设备数');

            // ---- 验证与禁用 ----
            $table->timestamp('last_verified_at')->nullable();
            $table->string('last_verify_ip', 45)->nullable();
            $table->timestamp('disabled_at')->nullable();
            $table->string('disabled_reason')->nullable();

            $table->text('note')->nullable();
            $table->foreignId('created_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();

            $table->index(['app_id', 'status']);
            $table->index(['type', 'status']);
            $table->index('created_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('card_keys');
    }
};
