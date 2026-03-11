<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Fixtures;

use Illuminate\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Override;

/**
 * @author Brian Faust <brian@cline.sh>
 */
final class TestUser extends Model implements AuthenticatableContract
{
    use HasFactory;
    use Authenticatable;

    #[Override()]
    public $timestamps = true;

    #[Override()]
    protected $table = 'users';

    #[Override()]
    protected $guarded = [];
}
