<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Configuration\Configuration;
use Cline\SSO\Exceptions\InvalidRouteMiddlewareException;
use Cline\SSO\Exceptions\InvalidScimRouteMiddlewareException;

it('rejects invalid web middleware configuration', function (): void {
    config()->set('sso.routes.middleware', ['web', '']);

    expect(fn (): array => Configuration::routes()->middleware())
        ->toThrow(InvalidRouteMiddlewareException::class);
});

it('rejects invalid scim middleware configuration', function (): void {
    config()->set('sso.routes.scim_middleware', ['api', '']);

    expect(fn (): array => Configuration::routes()->scimMiddleware())
        ->toThrow(InvalidScimRouteMiddlewareException::class);
});
