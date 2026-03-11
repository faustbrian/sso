<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Models;

use Cline\SSO\Configuration\Configuration;
use Cline\VariableKeys\Database\Concerns\HasVariablePrimaryKey;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Override;

/**
 * Eloquent model for the durable link between a provider-issued identity and a
 * local application principal.
 *
 * Each row captures the provider boundary, issuer, remote subject, and local
 * principal key chosen during sign-in or reconciliation. Together those values
 * form the package's persisted answer to the question "which local account does
 * this external identity belong to?" Subsequent logins can therefore skip
 * first-time discovery heuristics and resolve the same account deterministically.
 *
 * The model sits behind the default persistence adapters rather than the public
 * orchestration API. Repositories translate it into immutable records so
 * higher-level services can reason about identity links without depending on
 * Eloquent state, lazy loading, or host-application model subclasses.
 *
 * Important invariants:
 * - provider, issuer, and subject describe the remote identity boundary
 * - user_id stores the host application's local principal key
 * - email_snapshot is informational and may drift from the provider over time
 * - table and relation metadata are resolved from package configuration so the
 *   package can work with customized application models and table names
 *
 * @author Brian Faust <brian@cline.sh>
 * @property        null|string   $email_snapshot
 * @property        string        $id
 * @property        string        $issuer
 * @property        null|Model    $principal
 * @property        SsoProvider   $provider
 * @property        string        $sso_provider_id
 * @property        string        $subject
 * @property        string        $user_id
 * @method   static Builder<self> query()
 */
final class ExternalIdentity extends Model
{
    /** @use HasFactory<Factory<static>> */
    use HasFactory;
    use HasVariablePrimaryKey;

    #[Override()]
    protected $fillable = [
        'id',
        'user_id',
        'sso_provider_id',
        'issuer',
        'subject',
        'email_snapshot',
    ];

    /**
     * Return the local principal currently linked to this external identity.
     *
     * Resolution is fully configuration-driven: the related model class, local
     * foreign key column, and owner key are all taken from the package's
     * principal configuration. That keeps this persistence model aligned with
     * applications that rename user tables, swap authenticatable models, or use
     * non-standard primary keys.
     *
     * The relation is intentionally narrow in scope. It describes the durable
     * account link selected by the SSO flow; it does not re-run eligibility or
     * authorization rules.
     *
     * @return BelongsTo<Model, $this>
     */
    public function principal(): BelongsTo
    {
        /** @var class-string<Model> $modelClass */
        $modelClass = Configuration::principal()->model();

        $ownerKey = Configuration::principal()->ownerKey();

        $column = Configuration::principal()->foreignKeyColumn();

        return $this->belongsTo($modelClass, $column, $ownerKey);
    }

    /**
     * Return the provider record that owns this external identity mapping.
     *
     * Provider context is part of the natural uniqueness boundary because a
     * remote subject may only be unique within one provider and issuer scope.
     * Keeping the relationship explicit also gives administrative tooling a
     * reliable way to traverse from a linked identity back to the provider that
     * issued it.
     *
     * @return BelongsTo<SsoProvider, $this>
     */
    public function provider(): BelongsTo
    {
        return $this->belongsTo(SsoProvider::class, 'sso_provider_id');
    }

    /**
     * Return the configured table name for external identity persistence.
     *
     * Dynamic table resolution lets the package honor published configuration
     * changes without forcing consumers to subclass the model or override the
     * default repository implementation.
     */
    #[Override()]
    public function getTable(): string
    {
        return Configuration::tables()->externalIdentities();
    }
}
