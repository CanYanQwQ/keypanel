<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // 防重放：记录已使用的 nonce，超时后由清理任务删除
        Schema::create('api_nonces', function (Blueprint $table) {
            $table->id();
            $table->string('app_id', 64);
            $table->string('nonce', 128);
            $table->timestamp('expires_at')->index();
            $table->timestamp('created_at')->nullable();

            $table->unique(['app_id', 'nonce'], 'api_nonces_app_nonce_unique');
        });

        // 每个应用的每日调用计数，用于 daily_quota 限流
        Schema::create('app_daily_usages', function (Blueprint $table) {
            $table->id();
            $table->string('app_id', 64);
            $table->date('date');
            $table->unsignedInteger('total_calls')->default(0);
            $table->unsignedInteger('success_calls')->default(0);
            $table->unsignedInteger('failed_calls')->default(0);
            $table->timestamps();

            $table->unique(['app_id', 'date'], 'app_daily_usages_app_date_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('app_daily_usages');
        Schema::dropIfExists('api_nonces');
    }
};
