<?php

use App\Http\Controllers\Api\CardKeyController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API v1 Routes
|--------------------------------------------------------------------------
| 签名规范见 app/Support/ApiSigner.php，各语言对接模板见 docs/templates/
*/

Route::prefix('v1')
    ->middleware(['api.signature', 'api.ratelimit'])
    ->group(function () {
        Route::post('/verify', [CardKeyController::class, 'verify']);
        Route::post('/activate', [CardKeyController::class, 'activate']);
        Route::post('/consume', [CardKeyController::class, 'consume']);
        Route::post('/query', [CardKeyController::class, 'query']);
        Route::post('/unbind', [CardKeyController::class, 'unbind']);
    });