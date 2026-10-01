<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->alias([
            'api.signature' => \App\Http\Middleware\ApiSignatureAuth::class,
            'api.ratelimit' => \App\Http\Middleware\ApiRateLimiter::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->render(function (\App\Services\CardKeyException $e) {
            return response()->json([
                'code' => $e->errorCode->value,
                'message' => $e->errorCode->message(),
                'success' => false,
                'server_time' => now()->timestamp,
            ], $e->errorCode->httpStatus());
        });
    })->create();
