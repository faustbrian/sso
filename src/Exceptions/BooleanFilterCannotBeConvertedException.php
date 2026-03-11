<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Exceptions;

use LogicException;

/**
 * Thrown when code requires a strict boolean from an intentionally tri-state
 * filter value.
 *
 * `BooleanFilter` is used throughout repository criteria and configuration
 * reads to preserve the distinction between "true", "false", and "do not
 * constrain". This exception protects the package from silently collapsing the
 * `Any` state into a concrete boolean branch when a caller has reached a code
 * path that requires an explicit yes-or-no answer.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class BooleanFilterCannotBeConvertedException extends LogicException implements SsoException
{
    /**
     * Create an exception for converting the ambiguous `Any` case to bool.
     *
     * Callers use this when repository or configuration logic has deferred the
     * choice long enough that ambiguity is no longer valid and must be resolved
     * explicitly by the upstream caller.
     */
    public static function forAnyValue(): self
    {
        return new self('BooleanFilter::Any cannot be converted to a boolean value.');
    }
}
