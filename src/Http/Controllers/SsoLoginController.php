<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Http\Controllers;

use Cline\SSO\Configuration\Configuration;
use Cline\SSO\Contracts\AuditSinkInterface;
use Cline\SSO\Contracts\PrincipalResolverInterface;
use Cline\SSO\Data\ExternalIdentityRecord;
use Cline\SSO\Data\ProviderSearchCriteria;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\Drivers\SsoStrategyResolver;
use Cline\SSO\Enums\BooleanFilter;
use Cline\SSO\Exceptions\GuardNotStatefulException;
use Cline\SSO\Exceptions\SsoProviderNotFoundException;
use Cline\SSO\SsoManager;
use Cline\SSO\ValueObjects\ResolvedIdentity;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Exceptions\UrlGenerationException;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use RuntimeException;

use function __;
use function app;
use function is_array;
use function is_string;
use function now;
use function redirect;
use function route;
use function to_route;
use function view;

/**
 * Browser-facing controller for the interactive SSO login flow.
 *
 * The controller coordinates provider discovery, protocol redirects, callback
 * validation, local account resolution, and audit updates. Protocol-specific
 * details live in strategy classes while this controller enforces the package's
 * shared login lifecycle and persistence side effects.
 *
 * It is the main orchestration point for turning a successful external
 * identity assertion into a local Laravel session. As a result, it also owns
 * failure recording, session replay protection, and the ordering of account
 * linking heuristics. The abstraction exists so host applications can swap
 * strategies, repositories, and principal-resolution policies without
 * reimplementing the package's shared login lifecycle.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class SsoLoginController
{
    /**
     * @param SsoStrategyResolver        $strategies Resolves the concrete protocol
     *                                               strategy for each provider
     * @param AuthFactory                $auth       Factory used to obtain the
     *                                               configured stateful guard
     * @param SsoManager                 $sso        Orchestration service for
     *                                               provider and external identity
     *                                               persistence
     * @param PrincipalResolverInterface $principals Contract for principal
     *                                               lookup, linking, and provisioning
     * @param AuditSinkInterface         $audit      Sink for login success and
     *                                               failure events
     */
    public function __construct(
        private SsoStrategyResolver $strategies,
        private AuthFactory $auth,
        private SsoManager $sso,
        private PrincipalResolverInterface $principals,
        private AuditSinkInterface $audit,
    ) {}

    /**
     * Render the provider selection page for interactive logins.
     *
     * Only enabled providers are exposed, and the view receives a trimmed
     * display-focused payload rather than the full provider record. This keeps
     * sensitive provider configuration out of the rendered page while still
     * allowing applications to build a chooser UI. Provider ordering and
     * filtering are delegated to the repository-backed manager so the chooser
     * reflects the same persistence state used by redirects and callbacks.
     */
    public function index(): View
    {
        return view('sso::index', [
            'providers' => Collection::make($this->sso->searchProviders(
                new ProviderSearchCriteria(enabled: BooleanFilter::True),
            ))
                ->map(fn (SsoProviderRecord $provider): array => [
                    'id' => $provider->id,
                    'driver' => $provider->driver,
                    'scheme' => $provider->scheme,
                    'display_name' => $provider->displayName,
                    'is_default' => $provider->isDefault,
                ])->all(),
        ]);
    }

    /**
     * Start an outbound authorization flow for the requested scheme.
     *
     * The controller stores a provider-scoped state and nonce in session so the
     * callback can reject replayed or cross-provider responses. Those values are
     * removed during callback processing to keep each login attempt single-use.
     * Provider lookup happens before session mutation so disabled or unknown
     * schemes fail without leaving partial state behind.
     */
    public function redirect(Request $request, string $scheme): RedirectResponse
    {
        $provider = $this->resolveEnabledProvider($scheme);

        $state = Str::random(40);
        $nonce = Str::random(40);

        $request->session()->put('sso.'.$provider->scheme, [
            'state' => $state,
            'nonce' => $nonce,
        ]);

        return redirect()->away(
            $this->strategies->resolve($provider)->buildAuthorizationUrl($provider, $request, $state, $nonce),
        );
    }

    /**
     * Complete the external identity handshake and sign the principal in
     * locally.
     *
     * Valid callbacks update provider usage metrics, clear failure markers, and
     * emit audit records. Recoverable protocol failures are converted into the
     * same rejection path used for missing local accounts so operators see a
     * consistent failure trail regardless of where the login broke down.
     *
     * Resolution order after protocol validation is:
     * 1. Verify provider-scoped state from the single-use session payload.
     * 2. Normalize provider claims into a ResolvedIdentity via the strategy.
     * 3. Reconcile that identity to a local principal using package heuristics.
     * 4. Sign the principal in, regenerate the session, and persist audit data.
     */
    public function callback(Request $request, string $scheme): RedirectResponse
    {
        $provider = $this->resolveEnabledProvider($scheme);

        $session = $request->session()->pull('sso.'.$provider->scheme);
        $requestState = $request->input('state', $request->input('RelayState'));

        if (!is_array($session) || ($session['state'] ?? null) !== $requestState) {
            return $this->reject($provider, $this->message('sso::sso.login.errors.invalid_state'));
        }

        try {
            $identity = $this->strategies->resolve($provider)->resolveIdentity($provider, $request, $this->sessionNonce($session));
        } catch (RuntimeException $runtimeException) {
            return $this->reject($provider, $runtimeException->getMessage());
        }

        $principal = $this->resolvePrincipal($provider, $identity);

        if (!$principal instanceof Authenticatable || !$this->principals->canSignIn($provider, $principal)) {
            return $this->reject($provider, $this->message('sso::sso.login.errors.missing_local_account'));
        }

        $this->guard()->login($principal);
        $request->session()->regenerate();
        $this->principals->afterLogin($provider, $principal, $identity);
        $this->sso->updateProvider($provider->id, [
            'last_failure_reason' => null,
            'last_login_failed_at' => null,
            'last_login_succeeded_at' => now(),
            'last_used_at' => now(),
        ]);
        $this->audit->record('provider_login_succeeded', $provider, [
            'user_id' => $principal->getAuthIdentifier(),
        ]);

        return redirect($this->redirectTo());
    }

    /**
     * Record a failed login attempt and redirect back to the chooser page.
     *
     * Failure metadata is persisted before redirecting so operators can inspect
     * the most recent rejection reason in provider records and downstream audit
     * tooling can observe the failed attempt.
     */
    private function reject(SsoProviderRecord $provider, string $reason): RedirectResponse
    {
        $this->sso->updateProvider($provider->id, [
            'last_failure_reason' => $reason,
            'last_login_failed_at' => now(),
        ]);
        $this->audit->record('provider_login_failed', $provider, ['reason' => $reason]);

        return to_route($this->indexRouteName())->withErrors(['sso' => $reason]);
    }

    /**
     * Reconcile a resolved external identity to a local authenticatable
     * principal.
     *
     * Resolution order is:
     * 1. Existing provider/issuer/subject link.
     * 2. Email-based lookup when the identity supplies an email.
     * 3. Principal provisioning when the provider allows it.
     * 4. External identity linking once a local principal is approved.
     *
     * Returning `null` means the external login was valid but could not be
     * mapped to an allowed local account. The method never links an identity
     * unless the resolver first approves the principal for linking. When an
     * existing link is found, the denormalized email snapshot may be refreshed
     * as a side effect so support tooling reflects the latest upstream claim.
     */
    private function resolvePrincipal(
        SsoProviderRecord $provider,
        ResolvedIdentity $identity,
    ): ?Authenticatable {
        $settings = $provider->settingsMap();
        $externalIdentity = $this->sso->findExternalIdentity($provider->id, $identity->issuer, $identity->subject);

        if ($externalIdentity instanceof ExternalIdentityRecord) {
            if (is_string($identity->email) && $identity->email !== '' && $externalIdentity->emailSnapshot !== $identity->email) {
                $externalIdentity = $this->sso->saveExternalIdentity(
                    $externalIdentity->withEmailSnapshot($identity->email),
                );
            }

            return $this->principals->findPrincipalByExternalIdentity($provider, $externalIdentity);
        }

        if (!is_string($identity->email) || $identity->email === '') {
            return null;
        }

        $principal = $this->principals->findPrincipalByEmail($provider, $identity->email);

        if (!$principal instanceof Authenticatable && ($settings['provision_mode'] ?? 'link_only') !== 'link_only') {
            $principal = $this->principals->provisionPrincipal($provider, $identity);
        }

        if (!$principal instanceof Authenticatable || !$this->principals->canLinkPrincipal($provider, $principal, $identity)) {
            return null;
        }

        $this->sso->saveExternalIdentity(
            new ExternalIdentityRecord(
                id: null,
                emailSnapshot: $identity->email,
                issuer: $identity->issuer,
                linkedPrincipal: $this->principals->principalReference($principal),
                providerId: $provider->id,
                subject: $identity->subject,
            ),
        );

        return $principal;
    }

    /**
     * Resolve the configured stateful authentication guard.
     *
     * Non-stateful guards are treated as package misconfiguration because the
     * controller must establish a session-backed login. Failing fast here keeps
     * runtime login attempts from silently half-authenticating a principal.
     * The returned guard is the only point where the controller crosses from
     * external-identity resolution into Laravel session establishment.
     */
    private function guard(): StatefulGuard
    {
        $guard = $this->auth->guard($this->guardName());

        if (!$guard instanceof StatefulGuard) {
            throw GuardNotStatefulException::create();
        }

        return $guard;
    }

    /**
     * Return the configured login guard name.
     *
     * Indirection through configuration keeps the controller aligned with the
     * package's published auth contract and avoids hard-coding a specific guard
     * into the login workflow.
     */
    private function guardName(): string
    {
        return Configuration::auth()->guard();
    }

    /**
     * Determine the post-login redirect target.
     *
     * Named routes take precedence because they can remain locale-aware and
     * survive path changes. If route generation fails, the configured fallback
     * path is used instead. This ordering lets applications opt into route
     * generation without making successful login depend on every optional route
     * parameter being available in every deployment.
     */
    private function redirectTo(): string
    {
        $redirectRouteName = Configuration::login()->redirectRouteName();

        if ($redirectRouteName !== null) {
            try {
                return route($redirectRouteName, ['locale' => app()->getLocale()]);
            } catch (UrlGenerationException) {
                // Fall back to the configured path-based redirect below.
            }
        }

        return Configuration::login()->redirectPath();
    }

    /**
     * Return the route name used when redirecting failed logins.
     *
     * Centralizing this lookup keeps rejection handling aligned with the same
     * route configuration used to render the chooser UI.
     */
    private function indexRouteName(): string
    {
        return Configuration::routes()->indexName();
    }

    /**
     * Resolve an enabled provider by its public login scheme.
     *
     * Disabled and missing providers are both surfaced as `404` responses to
     * avoid disclosing which schemes exist but are unavailable. That keeps the
     * browser-facing login surface from leaking provider inventory through
     * distinct error modes.
     */
    private function resolveEnabledProvider(string $scheme): SsoProviderRecord
    {
        $provider = $this->sso->findProviderByScheme($scheme, true);

        if (!$provider instanceof SsoProviderRecord) {
            throw SsoProviderNotFoundException::forScheme($scheme);
        }

        return $provider;
    }

    /**
     * Resolve a translated message key into a stable string payload.
     *
     * Translation helpers may return non-string values in edge cases; falling
     * back to the key ensures audit records and validation bags still receive a
     * deterministic string reason.
     */
    private function message(string $key): string
    {
        $message = __($key);

        return is_string($message) ? $message : $key;
    }

    /**
     * Extract the nonce stored during redirect initiation.
     *
     * Missing or invalid nonces degrade to an empty string so strategy-specific
     * validation can reject the callback consistently.
     *
     * @param array<mixed> $session
     */
    private function sessionNonce(array $session): string
    {
        $nonce = $session['nonce'] ?? null;

        return is_string($nonce) ? $nonce : '';
    }
}
