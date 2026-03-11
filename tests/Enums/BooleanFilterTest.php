<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Enums\BooleanFilter;
use Cline\SSO\Exceptions\BooleanFilterCannotBeConvertedException;

it('converts concrete boolean filters to booleans', function (
    BooleanFilter $filter,
    bool $expected,
): void {
    expect($filter->toBool())->toBe($expected);
})->with([
    'true' => [BooleanFilter::True, true],
    'false' => [BooleanFilter::False, false],
]);

it('rejects converting the any filter to a boolean', function (): void {
    expect(fn (): bool => BooleanFilter::Any->toBool())
        ->toThrow(
            BooleanFilterCannotBeConvertedException::class,
            'BooleanFilter::Any cannot be converted to a boolean value.',
        );
});
