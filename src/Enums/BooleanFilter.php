<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Enums;

use Cline\SSO\Exceptions\BooleanFilterCannotBeConvertedException;

/**
 * Three-state filter used by repository criteria and configuration reads.
 *
 * Unlike a boolean, this enum can explicitly represent "do not constrain by
 * this field", which keeps repository criteria expressive without introducing
 * nullable booleans or parallel "apply filter" flags across the query layer.
 *
 * It is a small type, but it carries an important invariant: callers must opt
 * into ambiguity explicitly by choosing `Any`. Once a strict boolean is
 * required, that ambiguity must be resolved rather than silently coerced.
 *
 * @author Brian Faust <brian@cline.sh>
 */
enum BooleanFilter: string
{
    case Any = 'any';
    case False = 'false';
    case True = 'true';

    /**
     * Convert the enum to a concrete boolean when filtering is mandatory.
     *
     * `Any` is intentionally rejected because callers that require a strict
     * boolean should make that choice explicitly rather than silently default.
     * This prevents repository and configuration code from accidentally turning
     * "no filter" into an implicit truthy or falsy branch.
     */
    public function toBool(): bool
    {
        if ($this === self::Any) {
            throw BooleanFilterCannotBeConvertedException::forAnyValue();
        }

        return match ($this) {
            self::False => false,
            self::True => true,
        };
    }
}
