<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * API 限流中间件（按 AppID + IP 的滑动窗口，每分钟）。
 *
 * 路由组挂在 ApiSignatureAuth 之后，此时 request 已注入 _api_app 属性。
 * 依赖 Laravel 内置 RateLimiter 的 sliding window：attempts() 返回当前窗口内
 * 的累计次数，而窗口起点在第一个未过期计时器之后会自然前移。
 */
class ApiRateLimiter
{
    protected RateLimiter $limiter;

    public function __construct(RateLimiter $limiter)
    {
        $this->limiter = $limiter;
    }

    public function handle(Request $request, Closure $next): Response
    {
        /** @var \App\Models\App|null $app */
        $app = $request->attributes->get('_api_app');

        if ($app === null) {
            return $next($request);
        }

        $key = $this->buildKey($app->app_id, (string) $request->ip());
        $maxPerMinute = max(1, (int) ($app->rate_limit_per_minute ?? 60));

        if ($this->limiter->tooManyAttempts($key, $maxPerMinute)) {
            return response()->json([
                'code' => 1008,
                'message' => '请求过于频繁，请稍后再试',
                'success' => false,
                'server_time' => now()->timestamp,
            ], 429);
        }

        $this->limiter->hit($key, 60);

        return $next($request);
    }

    protected function buildKey(string $appId, string $ip): string
    {
        return "api_ratelimit:{$appId}:{$ip}";
    }
}
