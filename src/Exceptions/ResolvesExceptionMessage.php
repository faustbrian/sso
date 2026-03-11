<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

use function __;
use function is_string;

/**
 * Shared translation helper for package exception factories.
 *
 * The SSO package keeps message ownership inside the exception classes rather
 * than scattering translation-key selection across strategy, controller, and
 * provider code. This trait gives the abstract exception bases a single place
 * to resolve translated messages while preserving the existing fallback
 * behavior of returning the language key when a translation is unavailable.
 *
 * @author Brian Faust <brian@cline.sh>
 */
trait ResolvesExceptionMessage
{
    /**
     * Resolve a package translation key into the final exception message text.
     *
     * Exception factories use this so callers can throw semantic exception
     * types without also constructing message strings. Replacement values are
     * forwarded to Laravel's translator, and missing translations intentionally
     * fall back to the key for deterministic operator-facing diagnostics.
     *
     * @param array<string, scalar> $replace
     */
    protected static function translate(string $key, array $replace = []): string
    {
        $message = __($key, $replace);

        return is_string($message) ? $message : $key;
    }
}
