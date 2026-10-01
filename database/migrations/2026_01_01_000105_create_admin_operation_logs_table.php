<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('admin_operation_logs', function (Blueprint $table) {
            $table->id();

            $table->foreignId('user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->string('admin_name')->nullable()->comment('冗余管理员名，用户删除后仍可追溯');

            $table->string('action', 64)->index()->comment('如 card_key.batch_generate / app.reset_secret');
            $table->string('description');
            $table->string('target_type')->nullable();
            $table->string('target_id')->nullable();
            $table->json('changes')->nullable()->comment('变更前后摘要，敏感字段已脱敏');

            $table->string('ip', 45)->nullable();
            $table->string('user_agent')->nullable();

            $table->timestamp('created_at')->nullable()->index();

            $table->index(['user_id', 'created_at']);
            $table->index(['target_type', 'target_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('admin_operation_logs');
    }
};
