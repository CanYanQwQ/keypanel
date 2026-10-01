<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('verification_logs', function (Blueprint $table) {
            $table->id();

            $table->foreignId('app_id')->nullable()->constrained('apps')->nullOnDelete();
            $table->foreignId('card_key_id')->nullable()->constrained('card_keys')->nullOnDelete();

            // 安全要求：日志中不记录完整卡密明文，仅记录掩码
            $table->string('code_masked', 40)->nullable();

            $table->string('action', 16)->comment('verify/activate/consume/query/unbind');
            $table->string('result', 32)->comment('success 或错误码');
            $table->string('message')->nullable();

            $table->string('ip', 45)->nullable();
            $table->string('device_id', 191)->nullable();
            $table->string('user_agent')->nullable();
            $table->string('request_id', 64)->nullable()->index();
            $table->json('meta')->nullable();

            $table->timestamp('created_at')->nullable()->index();

            $table->index(['app_id', 'created_at']);
            $table->index(['result', 'created_at']);
            $table->index(['action', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('verification_logs');
    }
};
