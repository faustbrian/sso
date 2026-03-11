<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

/**
 * Thrown when the configured Laravel auth guard cannot establish a session.
 *
 * Interactive SSO login ends by calling `login()` on a `StatefulGuard`. This
 * exception marks a package composition error where the resolved guard exists
 * but does not support session-backed authentication, making the browser login
 * flow impossible to complete safely.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class GuardNotStatefulException extends LoginException
{
    /**
     * Create an exception for a non-stateful guard in the interactive login flow.
     *
     * The message is owned here so controllers can signal the failure by type
     * without rebuilding the package translation at each throw site.
     */
    public static function create(): self
    {
        return new self(self::translate('sso::sso.system.errors.guard_not_stateful'));
    }
}
