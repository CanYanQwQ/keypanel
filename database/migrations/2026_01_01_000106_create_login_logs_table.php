<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('login_logs', function (Blueprint $table) {
            $table->id();

            $table->foreignId('user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->string('email')->nullable();
            $table->string('result', 32)->comment('success / failed_password / failed_2fa / locked / logout');
            $table->string('message')->nullable();

            $table->string('ip', 45)->nullable();
            $table->string('user_agent')->nullable();

            $table->timestamp('created_at')->nullable()->index();

            $table->index(['result', 'created_at']);
        });

        Schema::table('users', function (Blueprint $table) {
            $table->timestamp('last_login_at')->nullable()->after('remember_token');
            $table->string('last_login_ip', 45)->nullable()->after('last_login_at');
            $table->unsignedInteger('failed_login_attempts')->default(0)->after('last_login_ip');
            $table->timestamp('locked_until')->nullable()->after('failed_login_attempts');
            $table->boolean('must_change_password')->default(false)->after('locked_until');
            $table->timestamp('password_changed_at')->nullable()->after('must_change_password');
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn([
                'last_login_at', 'last_login_ip', 'failed_login_attempts',
                'locked_until', 'must_change_password', 'password_changed_at',
            ]);
        });

        Schema::dropIfExists('login_logs');
    }
};
