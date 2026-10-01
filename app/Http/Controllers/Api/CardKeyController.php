<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\App;
use App\Models\AppDailyUsage;
use App\Services\CardKeyService;
use App\Services\SettingsService;
use App\Support\ApiSigner;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

/**
 * /api/v1 卡密接口。
 *
 * 每个方法调用前已经过 ApiSignatureAuth 中间件签名、防重放、IP白名单、每日配额校验，
 * 所以这里只聚焦业务编排。
 */
class CardKeyController extends Controller
{
    public function __construct(protected CardKeyService $service) {}

    /**
     * POST /api/v1/verify
     */
    public function verify(Request $request): JsonResponse
    {
        $data = $request->validate([
            'card_key' => 'required',
            'device_id' => 'nullable|string|max:191',
        ]);

        /** @var App $app */
        $app = $request->attributes->get('_api_app');

        $code = $this->service->decryptSubmittedCode($data['card_key'], $app);
        $outcome = $this->service->verify($code, $app, $data['device_id'] ?? null, $request->ip(), $request->userAgent(), $this->requestId($request));

        $this->tickUsage($app, $outcome->success);

        return $this->respond($request, $app, $outcome);
    }

    /**
     * POST /api/v1/activate
     */
    public function activate(Request $request): JsonResponse
    {
        $data = $request->validate([
            'card_key' => 'required',
            'device_id' => 'nullable|string|max:191',
        ]);

        /** @var App $app */
        $app = $request->attributes->get('_api_app');

        $code = $this->service->decryptSubmittedCode($data['card_key'], $app);
        $outcome = $this->service->activate($code, $app, $data['device_id'] ?? null, $request->ip(), $request->userAgent(), $this->requestId($request));

        $this->tickUsage($app, $outcome->success);

        return $this->respond($request, $app, $outcome);
    }

    /**
     * POST /api/v1/consume
     */
    public function consume(Request $request): JsonResponse
    {
        $data = $request->validate([
            'card_key' => 'required',
            'device_id' => 'nullable|string|max:191',
            'count' => 'integer|min:1|max:1000',
        ]);

        /** @var App $app */
        $app = $request->attributes->get('_api_app');

        $code = $this->service->decryptSubmittedCode($data['card_key'], $app);
        $outcome = $this->service->consume($code, $app, $data['device_id'] ?? null, (int) ($data['count'] ?? 1), $request->ip(), $request->userAgent(), $this->requestId($request));

        $this->tickUsage($app, $outcome->success);

        return $this->respond($request, $app, $outcome);
    }

    /**
     * POST /api/v1/query
     */
    public function query(Request $request): JsonResponse
    {
        $data = $request->validate([
            'card_key' => 'required',
            'device_id' => 'nullable|string|max:191',
        ]);

        /** @var App $app */
        $app = $request->attributes->get('_api_app');

        $code = $this->service->decryptSubmittedCode($data['card_key'], $app);
        $outcome = $this->service->query($code, $app, $data['device_id'] ?? null, $request->ip(), $request->userAgent(), $this->requestId($request));

        $this->tickUsage($app, $outcome->success);

        return $this->respond($request, $app, $outcome);
    }

    /**
     * POST /api/v1/unbind
     */
    public function unbind(Request $request): JsonResponse
    {
        $data = $request->validate([
            'card_key' => 'required',
            'device_id' => 'nullable|string|max:191',
            'force' => 'boolean',
        ]);

        /** @var App $app */
        $app = $request->attributes->get('_api_app');

        $code = $this->service->decryptSubmittedCode($data['card_key'], $app);
        $outcome = $this->service->unbind($code, $app, $data['device_id'] ?? null, (bool) ($data['force'] ?? false), $request->ip(), $request->userAgent(), $this->requestId($request));

        $this->tickUsage($app, $outcome->success);

        return $this->respond($request, $app, $outcome);
    }

    // ==================================================================
    private function respond(Request $request, App $app, mixed $outcome): JsonResponse
    {
        $body = $outcome->toApiResponse();
        $json = json_encode($body, JSON_UNESCAPED_UNICODE);

        $timestamp = $request->attributes->get('_api_timestamp', (string) time());
        $nonce = $request->attributes->get('_api_nonce', ApiSigner::generateNonce());

        $headers = [
            'Content-Type' => 'application/json; charset=utf-8',
        ];

        if (SettingsService::getBool('api.response_signature', true)) {
            $headers['X-Response-Signature'] = ApiSigner::signResponse($app->app_secret, $json, (string) $timestamp, $nonce);
            $headers['X-Response-Timestamp'] = $timestamp;
        }

        return response()->json($body, $outcome->code->httpStatus(), $headers, JSON_UNESCAPED_UNICODE);
    }

    private function tickUsage(App $app, bool $success): void
    {
        $today = now()->toDateString();

        $usage = AppDailyUsage::firstOrCreate(
            ['app_id' => $app->app_id, 'date' => $today],
            ['total_calls' => 0, 'success_calls' => 0, 'failed_calls' => 0],
        );

        $usage->increment('total_calls');

        if ($success) {
            $usage->increment('success_calls');
        } else {
            $usage->increment('failed_calls');
        }
    }

    private function requestId(Request $request): string
    {
        return $request->header('X-Request-Id', (string) Str::uuid());
    }
}