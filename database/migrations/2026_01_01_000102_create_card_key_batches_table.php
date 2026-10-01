<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('card_key_batches', function (Blueprint $table) {
            $table->id();

            $table->string('batch_no', 40)->unique();
            $table->foreignId('app_id')->nullable()->constrained('apps')->nullOnDelete();

            $table->string('type', 16);
            $table->unsignedInteger('quantity');
            $table->unsignedInteger('duration_value')->nullable()->comment('时间卡/试用卡有效时长');
            $table->string('duration_unit', 8)->nullable()->comment('时长单位：minute/hour/day/month');
            $table->unsignedInteger('max_uses')->nullable()->comment('次数卡可用次数');
            $table->string('code_prefix', 16)->nullable()->comment('卡密前缀，便于人工识别');

            $table->text('note')->nullable();
            $table->foreignId('created_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();

            $table->index(['app_id', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('card_key_batches');
    }
};
