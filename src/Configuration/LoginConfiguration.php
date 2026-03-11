<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Configuration;

use Illuminate\Support\Facades\Config;

use function is_string;

/**
 * Reads browser-login settings used after successful interactive SSO
 * authentication.
 *
 * Once an external identity has been validated and associated with a local
 * user, the package must hand control back to the host application. This
 * reader encapsulates the redirect policy for that final step so controllers
 * can apply a consistent precedence order without parsing raw configuration.
 *
 * The package supports both direct path redirects and named-route redirects.
 * Named routes take priority when present because they are more resilient to
 * URL structure changes inside the host application.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class LoginConfiguration
{
    /**
     * Return the fallback path used when no redirect route name is configured.
     *
     * This path acts as the stable default for successful browser logins when
     * the application does not opt into route-name based redirection.
     */
    public function redirectPath(): string
    {
        return Config::string('sso.login.redirect_to', '/');
    }

    /**
     * Return the preferred named route for post-login redirects, if any.
     *
     * Empty or non-string configuration values are normalized to `null` so
     * callers can reliably fall back to {@see redirectPath()} without having to
     * repeat validation logic. Controllers should treat a non-null result as
     * the authoritative redirect target.
     */
    public function redirectRouteName(): ?string
    {
        $routeName = Config::get('sso.login.redirect_route_name');

        return is_string($routeName) && $routeName !== '' ? $routeName : null;
    }
}
