<?php declare(strict_types=1);

use Cline\SSO\Configuration\Configuration;
use Cline\SSO\Http\Controllers\Scim\ScimGroupController;
use Cline\SSO\Http\Controllers\Scim\ScimResourceTypeController;
use Cline\SSO\Http\Controllers\Scim\ScimSchemaController;
use Cline\SSO\Http\Controllers\Scim\ScimServiceProviderConfigController;
use Cline\SSO\Http\Controllers\Scim\ScimUserController;
use Illuminate\Support\Facades\Route;

Route::middleware(Configuration::routes()->scimMiddleware())
    ->prefix(Configuration::routes()->scimPrefix())
    ->as(Configuration::routes()->scimNamePrefix())
    ->group(function (): void {
        Route::get('ServiceProviderConfig', ScimServiceProviderConfigController::class)->name('service-provider-config');
        Route::get('Schemas', [ScimSchemaController::class, 'index'])->name('schemas.index');
        Route::get('ResourceTypes', [ScimResourceTypeController::class, 'index'])->name('resource-types.index');
        Route::get('Users', [ScimUserController::class, 'index'])->name('users.index');
        Route::post('Users', [ScimUserController::class, 'store'])->name('users.store');
        Route::get('Users/{user}', [ScimUserController::class, 'show'])->name('users.show');
        Route::put('Users/{user}', [ScimUserController::class, 'replace'])->name('users.replace');
        Route::patch('Users/{user}', [ScimUserController::class, 'patch'])->name('users.patch');
        Route::get('Groups', [ScimGroupController::class, 'index'])->name('groups.index');
        Route::post('Groups', [ScimGroupController::class, 'store'])->name('groups.store');
        Route::get('Groups/{group}', [ScimGroupController::class, 'show'])->name('groups.show');
        Route::patch('Groups/{group}', [ScimGroupController::class, 'patch'])->name('groups.patch');
        Route::delete('Groups/{group}', [ScimGroupController::class, 'destroy'])->name('groups.destroy');
    });
