<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

use function sprintf;

/**
 * Thrown when interactive login flow lookup cannot resolve a provider scheme.
 *
 * This failure sits at the HTTP boundary for browser-based SSO routes. It
 * indicates that the requested scheme did not map to an enabled provider
 * record, so the package aborts before it mutates session state or delegates
 * to a protocol strategy.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class SsoProviderNotFoundException extends NotFoundHttpException implements SsoException
{
    /**
     * Create an exception for a missing or disabled provider scheme.
     *
     * @param  string $scheme The route scheme segment that failed resolution
     * @return self   Exception instance suitable for HTTP 404 handling
     */
    public static function forScheme(string $scheme): self
    {
        return new self(sprintf('SSO provider [%s] was not found.', $scheme));
    }
}
