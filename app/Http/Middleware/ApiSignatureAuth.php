<?php

namespace App\Http\Middleware;

use App\Enums\ApiErrorCode;
use App\Models\ApiNonce;
use App\Models\App;
use App\Models\AppDailyUsage;
use App\Services\SettingsService;
use App\Support\ApiSigner;
use Carbon\Carbon;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

/**
 * API 认证中间件：校验签名、防重放、IP 白名单、限流。
 *
 * 在路由组中绑定，所有 /api/v1/* 请求先过此中间件。
 */
class ApiSignatureAuth
{
    /**
     * @return \Illuminate\Http\JsonResponse|Response
     */
    public function handle(Request $request, Closure $next): Response
    {
        // 1. 读取必需头
        $appId = $request->header(ApiSigner::HEADER_APP_ID);
        $timestamp = $request->header(ApiSigner::HEADER_TIMESTAMP);
        $nonce = $request->header(ApiSigner::HEADER_NONCE);
        $signature = $request->header(ApiSigner::HEADER_SIGNATURE);

        if (blank($appId) || blank($timestamp) || blank($nonce) || blank($signature)) {
            return $this->reject(ApiErrorCode::MissingCredentials);
        }

        // 2. 查找应用
        /** @var App|null $app */
        $app = App::where('app_id', $appId)->first();

        if ($app === null) {
            return $this->reject(ApiErrorCode::AppNotFound);
        }

        if (! $app->isEnabled()) {
            return $this->reject(ApiErrorCode::AppDisabled);
        }

        // 3. IP 白名单
        if (! $app->isIpAllowed($request->ip())) {
            return $this->reject(ApiErrorCode::IpNotAllowed);
        }

        // 4. 时间戳校验
        $serverTs = time();
        $tolerance = $app->timestamp_tolerance ?: SettingsService::getInt('api.timestamp_tolerance');

        if (! is_numeric($timestamp) || abs($serverTs - (int) $timestamp) > $tolerance) {
            return $this->reject(ApiErrorCode::TimestampExpired);
        }

        // 5. 校验签名版本
        if ($request->header(ApiSigner::HEADER_VERSION) !== ApiSigner::VERSION) {
            return $this->reject(ApiErrorCode::SignatureInvalid);
        }

        // 6. 校验签名（先验签后记录 nonce，防止未签名请求灌满 nonce 表）
        $rawBody = (string) $request->getContent();
        $path = $request->getPathInfo();

        $canonical = ApiSigner::canonicalString(
            $request->method(),
            $path,
            (string) $timestamp,
            (string) $nonce,
            $rawBody,
        );

        if (! ApiSigner::verify($app->app_secret, $canonical, $signature)) {
            return $this->reject(ApiErrorCode::SignatureInvalid);
        }

        // 7. 防重放（插入 nonce，利用唯一索引防并发）
        $nonceTtl = SettingsService::getInt('api.nonce_ttl');

        try {
            ApiNonce::create([
                'app_id' => $appId,
                'nonce' => $nonce,
                'expires_at' => Carbon::now()->addSeconds($nonceTtl),
                'created_at' => now(),
            ]);
        } catch (\Illuminate\Database\UniqueConstraintViolationException) {
            return $this->reject(ApiErrorCode::NonceReused);
        }

        // 8. 每日配额
        if ($app->daily_quota !== null && $app->daily_quota > 0) {
            $today = now()->toDateString();
            $usage = AppDailyUsage::firstOrCreate(
                ['app_id' => $appId, 'date' => $today],
                ['total_calls' => 0, 'success_calls' => 0, 'failed_calls' => 0],
            );

            if ($usage->total_calls >= $app->daily_quota) {
                return $this->reject(ApiErrorCode::DailyQuotaExceeded);
            }
        }

        // 9. 签到：注入认证元数据与原始摘要到 request attributes
        $request->attributes->set('_api_app_id', $appId);
        $request->attributes->set('_api_timestamp', $timestamp);
        $request->attributes->set('_api_nonce', $nonce);
        $request->attributes->set('_api_app', $app);
        $request->attributes->set('_api_raw_body', $rawBody);

        return $next($request);
    }

    protected function reject(ApiErrorCode $code): \Illuminate\Http\JsonResponse
    {
        return response()->json([
            'code' => $code->value,
            'message' => $code->message(),
            'success' => false,
            'server_time' => now()->timestamp,
        ], $code->httpStatus());
    }
}