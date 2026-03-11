<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Data;

use Cline\SSO\Enums\BooleanFilter;

/**
 * Immutable filter object for provider repository queries.
 *
 * Administrative screens, console commands, jobs, and runtime login flows all
 * need to select providers using the same vocabulary. This value object keeps
 * that vocabulary explicit and reusable so the repository can implement one
 * coherent set of filtering rules for enablement, SSO enforcement, ownership,
 * scheme selection, and SCIM capability.
 *
 * BooleanFilter values deliberately model three states rather than a raw
 * boolean so callers can express "must be true", "must be false", or "do not
 * filter on this dimension" without auxiliary flags. That distinction matters
 * because several call sites need to differentiate "disabled providers only"
 * from "all providers regardless of disabled state", and a nullable bool would
 * make that intent less explicit.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class ProviderSearchCriteria
{
    /**
     * @param array<int, string> $schemes Schemes to include; an empty list means
     *                                    no scheme filter, while a populated
     *                                    list narrows results to those exact
     *                                    public login identifiers
     */
    public function __construct(
        public BooleanFilter $enabled = BooleanFilter::Any,
        public BooleanFilter $enforceSso = BooleanFilter::Any,
        public ?OwnerReference $owner = null,
        public array $schemes = [],
        public BooleanFilter $scimEnabled = BooleanFilter::Any,
    ) {}
}
