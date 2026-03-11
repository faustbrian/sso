<?php declare(strict_types=1);

use Cline\SSO\Configuration\Configuration;
use Cline\SSO\Http\Controllers\SsoLoginController;
use Illuminate\Support\Facades\Route;

Route::middleware(Configuration::routes()->middleware())
    ->prefix(Configuration::routes()->prefix())
    ->as(Configuration::routes()->namePrefix())
    ->group(function (): void {
        Route::get('/', [SsoLoginController::class, 'index'])->name('index');
        Route::get('/{scheme}/redirect', [SsoLoginController::class, 'redirect'])->name('redirect');
        Route::match(['get', 'post'], '/{scheme}/callback', [SsoLoginController::class, 'callback'])->name('callback');
    });
