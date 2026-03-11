<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\SSO\Drivers\Saml;

use Carbon\CarbonImmutable;
use Cline\SSO\Configuration\Configuration;
use Cline\SSO\Contracts\SsoStrategy;
use Cline\SSO\Data\SsoProviderRecord;
use Cline\SSO\Exceptions\ExpiredSamlAssertionException;
use Cline\SSO\Exceptions\InvalidSamlAudienceException;
use Cline\SSO\Exceptions\InvalidSamlDestinationException;
use Cline\SSO\Exceptions\InvalidSamlIssuerException;
use Cline\SSO\Exceptions\InvalidSamlMetadataXmlException;
use Cline\SSO\Exceptions\InvalidSamlRecipientException;
use Cline\SSO\Exceptions\InvalidSamlRequestBindingException;
use Cline\SSO\Exceptions\InvalidSamlResponseXmlException;
use Cline\SSO\Exceptions\InvalidSamlSignatureException;
use Cline\SSO\Exceptions\InvalidSamlStatusException;
use Cline\SSO\Exceptions\MissingAuthnRequestSigningKeyException;
use Cline\SSO\Exceptions\MissingExpectedSamlIssuerException;
use Cline\SSO\Exceptions\MissingSamlIdentityClaimsException;
use Cline\SSO\Exceptions\MissingSamlResponseException;
use Cline\SSO\Exceptions\MissingSamlSignatureException;
use Cline\SSO\Exceptions\MissingSamlSigningCertificatesException;
use Cline\SSO\Exceptions\MissingSamlSigningKeyException;
use Cline\SSO\Exceptions\MissingSingleSignOnUrlException;
use Cline\SSO\Exceptions\SamlAssertionNotYetValidException;
use Cline\SSO\Exceptions\UndecodableSamlResponseException;
use Cline\SSO\Exceptions\UnsignedAuthnRequestException;
use Cline\SSO\ValueObjects\ResolvedIdentity;
use DateTimeImmutable;
use DOMDocument;
use DOMElement;
use DOMNode;
use DOMNodeList;
use DOMXPath;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

use const FILTER_VALIDATE_EMAIL;
use const LIBXML_NOBLANKS;
use const LIBXML_NOCDATA;
use const LIBXML_NONET;
use const OPENSSL_ALGO_SHA1;
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_ALGO_SHA384;
use const OPENSSL_ALGO_SHA512;

use function array_filter;
use function base64_decode;
use function base64_encode;
use function chunk_split;
use function collect;
use function count;
use function filter_var;
use function gzdeflate;
use function hash;
use function hash_equals;
use function in_array;
use function is_array;
use function is_string;
use function mb_rtrim;
use function mb_trim;
use function now;
use function openssl_sign;
use function openssl_verify;
use function preg_replace;
use function rawurlencode;
use function route;
use function sha1;
use function sprintf;
use function str_contains;
use function str_ends_with;

/**
 * Implements a SAML 2.0 browser SSO flow for configured identity providers.
 *
 * The strategy builds AuthnRequests, validates signed SAML responses, imports
 * metadata from remote descriptors, and normalizes assertion data into the
 * package's resolved-identity abstraction. It encapsulates the XML-heavy and
 * signature-sensitive parts of the package so the rest of the login lifecycle
 * can remain protocol-agnostic.
 *
 * The implementation treats SAML validation as a sequence of explicit trust
 * gates: document integrity, request binding, destination and recipient
 * matching, temporal validity, audience restrictions, and optional issuer
 * enforcement. Only after those checks pass is an identity considered trusted.
 *
 * @author Brian Faust <brian@cline.sh>
 * @psalm-immutable
 */
final readonly class SamlStrategy implements SsoStrategy
{
    public function __construct(
        private HttpFactory $http,
    ) {}

    /**
     * Build the redirect URL that initiates a SAML login transaction.
     *
     * Depending on provider configuration the generated AuthnRequest may be
     * signed before being encoded onto the redirect query string. The nonce is
     * embedded into the request so the callback can later be tied back to this
     * specific login attempt.
     */
    public function buildAuthorizationUrl(SsoProviderRecord $provider, Request $request, string $state, string $nonce): string
    {
        $settings = $provider->settingsMap();
        $compressedRequest = gzdeflate($this->buildAuthnRequest($provider, $nonce), 9);

        if (!is_string($compressedRequest) || $compressedRequest === '') {
            throw UnsignedAuthnRequestException::create();
        }

        $queryParameters = [
            'SAMLRequest' => base64_encode($compressedRequest),
            'RelayState' => $state,
        ];

        if (!$this->shouldSignAuthnRequest($provider)) {
            return mb_rtrim($provider->authority, '/').'?'.$this->buildRedirectQueryString($queryParameters);
        }

        $signatureAlgorithm = $this->settingString(
            $settings,
            'signature_algorithm',
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        );

        $queryParameters['SigAlg'] = $signatureAlgorithm;
        $payload = $this->buildRedirectQueryString($queryParameters);
        $signature = $this->signRedirectPayload($payload, $provider->clientSecret, $signatureAlgorithm);

        return mb_rtrim($provider->authority, '/').'?'.$payload.'&Signature='.rawurlencode(base64_encode($signature));
    }

    /**
     * Validate the inbound SAML response and extract the authenticated subject.
     *
     * The assertion must satisfy signature, request binding, destination,
     * recipient, timing, audience, and optional issuer checks before an
     * identity is considered trusted. Missing required elements or malformed
     * XML are treated as hard failures rather than partial identities.
     */
    public function resolveIdentity(SsoProviderRecord $provider, Request $request, string $nonce): ResolvedIdentity
    {
        $encodedResponse = $request->input('SAMLResponse');

        if (!is_string($encodedResponse) || $encodedResponse === '') {
            throw MissingSamlResponseException::create();
        }

        $xml = base64_decode($encodedResponse, true);

        if (!is_string($xml) || $xml === '') {
            throw UndecodableSamlResponseException::create();
        }

        $document = new DOMDocument();

        if ($document->loadXML($xml, LIBXML_NONET | LIBXML_NOBLANKS | LIBXML_NOCDATA) === false) {
            throw InvalidSamlResponseXmlException::create();
        }

        $xpath = $this->createXPath($document);

        $this->assertSuccessfulStatus($xpath);
        $this->assertSignedDocument($provider, $document, $xpath);
        $this->assertResponseBoundToRequest($xpath, $nonce);
        $this->assertDestinationMatches($provider, $xpath);
        $this->assertRecipientMatches($provider, $xpath);
        $this->assertTemporalConditions($xpath);
        $this->assertAudienceMatches($provider, $xpath);

        $issuer = $this->resolveIssuer($xpath);
        $subject = $this->stringValue($xpath, 'string((//saml:Assertion/saml:Subject/saml:NameID)[1])');

        if ($issuer === '' || $subject === '') {
            throw MissingSamlIdentityClaimsException::create();
        }

        $validIssuer = $this->resolveExpectedIssuer($provider);

        if ($provider->validateIssuer && $validIssuer !== null && $validIssuer !== '' && $issuer !== $validIssuer) {
            throw InvalidSamlIssuerException::create();
        }

        $attributes = $this->resolveAttributes($xpath);

        return new ResolvedIdentity(
            attributes: $attributes,
            email: $this->resolveEmail($provider, $xpath, $attributes),
            issuer: $issuer,
            subject: $subject,
        );
    }

    /**
     * Validate provider metadata, certificates, and request-signing settings.
     *
     * This method is used by administrative validation and metadata refresh
     * workflows to confirm that the provider exposes enough trusted material to
     * verify future SAML responses.
     *
     * @return array<string, null|scalar>
     */
    public function validateConfiguration(SsoProviderRecord $provider): array
    {
        $settings = $provider->settingsMap();
        $this->resolveMetadata($provider);
        $trustedCertificates = $this->resolveTrustedCertificates($provider);
        $expectedIssuer = $this->resolveExpectedIssuer($provider);

        if ($trustedCertificates === []) {
            throw MissingSamlSigningCertificatesException::create();
        }

        if ($provider->validateIssuer && ($expectedIssuer === null || $expectedIssuer === '')) {
            throw MissingExpectedSamlIssuerException::create();
        }

        if ($this->shouldSignAuthnRequest($provider) && $provider->clientSecret === '') {
            throw MissingSamlSigningKeyException::create();
        }

        return [
            'issuer' => $expectedIssuer,
            'metadata_url' => is_string(Arr::get($settings, 'metadata_url'))
                ? Arr::get($settings, 'metadata_url')
                : null,
            'sign_authn_request' => $this->shouldSignAuthnRequest($provider),
            'signing_certificates' => count($trustedCertificates),
        ];
    }

    /**
     * Import canonical metadata values from the provider's descriptor document.
     *
     * @return array{
     *     authority: null|string,
     *     settings: array<string, mixed>,
     *     valid_issuer: null|string
     * }
     */
    public function importConfiguration(SsoProviderRecord $provider): array
    {
        $settings = $provider->settingsMap();
        $metadata = $this->resolveMetadata($provider);

        if (($metadata['sso_url'] ?? null) === null || $metadata['sso_url'] === '') {
            throw MissingSingleSignOnUrlException::create();
        }

        return [
            'authority' => $metadata['sso_url'],
            'settings' => array_filter([
                'metadata_url' => Arr::get($settings, 'metadata_url'),
                'x509_certificates' => $metadata['certificates'],
            ], fn (mixed $value): bool => $value !== null),
            'valid_issuer' => $metadata['entity_id'] ?? null,
        ];
    }

    /**
     * Clear cached metadata before re-running validation against fresh data.
     *
     * @return array<string, null|scalar>
     */
    public function refreshMetadata(SsoProviderRecord $provider): array
    {
        $cacheKey = $this->metadataCacheKey($provider);

        if ($cacheKey !== null) {
            Cache::forget($cacheKey);
        }

        return $this->validateConfiguration($provider);
    }

    private function buildAuthnRequest(SsoProviderRecord $provider, string $requestId): string
    {
        $settings = $provider->settingsMap();
        $issueInstant = now()->toIso8601String();
        $destination = mb_rtrim($provider->authority, '/');
        $assertionConsumerServiceUrl = $this->callbackUrl($provider);
        $nameIdFormat = $this->settingString(
            $settings,
            'name_id_format',
            'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        );

        return <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{$requestId}" Version="2.0" IssueInstant="{$issueInstant}" Destination="{$destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{$assertionConsumerServiceUrl}">
  <saml:Issuer>{$provider->clientId}</saml:Issuer>
  <samlp:NameIDPolicy AllowCreate="true" Format="{$nameIdFormat}" />
</samlp:AuthnRequest>
XML;
    }

    private function shouldSignAuthnRequest(SsoProviderRecord $provider): bool
    {
        return Arr::get($provider->settingsMap(), 'sign_authn_request', false) === true;
    }

    /**
     * @param array<string, string> $parameters
     */
    private function buildRedirectQueryString(array $parameters): string
    {
        return collect($parameters)
            ->map(fn (string $value, string $key): string => rawurlencode($key).'='.rawurlencode($value))
            ->implode('&');
    }

    private function signRedirectPayload(string $payload, string $privateKey, string $signatureAlgorithm): string
    {
        if ($privateKey === '') {
            throw MissingAuthnRequestSigningKeyException::create();
        }

        $opensslAlgorithm = $this->resolveSignatureAlgorithm($signatureAlgorithm);

        $signed = openssl_sign($payload, $signature, $privateKey, $opensslAlgorithm);

        if (!$signed) {
            throw UnsignedAuthnRequestException::create();
        }

        return is_string($signature) ? $signature : '';
    }

    private function assertSuccessfulStatus(DOMXPath $xpath): void
    {
        $statusCode = $this->stringValue($xpath, 'string((//samlp:StatusCode/@Value)[1])');

        if ($statusCode !== 'urn:oasis:names:tc:SAML:2.0:status:Success') {
            throw InvalidSamlStatusException::create();
        }
    }

    private function assertSignedDocument(SsoProviderRecord $provider, DOMDocument $document, DOMXPath $xpath): void
    {
        $requireSignature = Arr::get($provider->settingsMap(), 'require_signature', true) !== false;
        $signedElements = $this->resolveSignedElements($xpath);

        if ($signedElements === []) {
            if ($requireSignature) {
                throw MissingSamlSignatureException::create();
            }

            return;
        }

        $trustedCertificates = $this->resolveTrustedCertificates($provider);

        if ($trustedCertificates === []) {
            throw MissingSamlSigningCertificatesException::create();
        }

        foreach ($signedElements as $element) {
            if ($this->verifyElementSignature($document, $element, $trustedCertificates)) {
                return;
            }
        }

        throw InvalidSamlSignatureException::create();
    }

    /**
     * @return array<int, DOMElement>
     */
    private function resolveSignedElements(DOMXPath $xpath): array
    {
        $elements = [];

        foreach (['/samlp:Response', '//saml:Assertion'] as $expression) {
            $nodes = $xpath->query($expression);

            if (!$nodes instanceof DOMNodeList) {
                continue;
            }

            foreach ($nodes as $node) {
                if (!$node instanceof DOMElement) {
                    continue;
                }

                if (!$node->ownerDocument instanceof DOMDocument) {
                    continue;
                }

                $signatureNodes = $this->createXPath($node->ownerDocument)->query('./ds:Signature', $node);

                if (!$signatureNodes instanceof DOMNodeList) {
                    continue;
                }

                if ($signatureNodes->length <= 0) {
                    continue;
                }

                $elements[] = $node;
            }
        }

        return $elements;
    }

    /**
     * @param array<int, string> $trustedCertificates
     */
    private function verifyElementSignature(DOMDocument $document, DOMElement $signedElement, array $trustedCertificates): bool
    {
        $xpath = $this->createXPath($document);
        $signatureNodes = $xpath->query('./ds:Signature', $signedElement);
        $signatureNode = $signatureNodes instanceof DOMNodeList ? $signatureNodes->item(0) : null;

        if (!$signatureNode instanceof DOMElement) {
            return false;
        }

        $signedInfoNodes = $xpath->query('./ds:SignedInfo', $signatureNode);
        $signedInfo = $signedInfoNodes instanceof DOMNodeList ? $signedInfoNodes->item(0) : null;
        $signatureValue = $this->stringValue($xpath, 'string(./ds:SignatureValue)', $signatureNode);

        if (!$signedInfo instanceof DOMElement || $signatureValue === '') {
            return false;
        }

        $references = $xpath->query('./ds:Reference', $signedInfo);

        if (!$references instanceof DOMNodeList || $references->length === 0) {
            return false;
        }

        foreach ($references as $reference) {
            if (!$reference instanceof DOMElement || !$this->assertReferenceDigestMatches($signedElement, $reference)) {
                return false;
            }
        }

        $canonicalizationAlgorithm = $this->stringValue($xpath, 'string(./ds:CanonicalizationMethod/@Algorithm)', $signedInfo);
        $canonicalSignedInfo = $this->canonicalizeNode($signedInfo, $canonicalizationAlgorithm);

        if ($canonicalSignedInfo === null) {
            return false;
        }

        $signatureAlgorithm = $this->stringValue($xpath, 'string(./ds:SignatureMethod/@Algorithm)', $signedInfo);
        $opensslAlgorithm = $this->resolveSignatureAlgorithm($signatureAlgorithm);
        $decodedSignature = base64_decode($signatureValue, true);

        if (!is_string($decodedSignature) || $decodedSignature === '') {
            return false;
        }

        foreach ($trustedCertificates as $certificate) {
            $verified = openssl_verify($canonicalSignedInfo, $decodedSignature, $certificate, $opensslAlgorithm);

            if ($verified === 1) {
                return true;
            }
        }

        return false;
    }

    private function assertReferenceDigestMatches(DOMElement $signedElement, DOMElement $reference): bool
    {
        $referenceUri = $reference->getAttribute('URI');
        $signedElementId = $signedElement->getAttribute('ID');

        if ($referenceUri === '' || $signedElementId === '' || $referenceUri !== '#'.$signedElementId) {
            return false;
        }

        $clone = $signedElement->cloneNode(true);

        if (!$clone instanceof DOMElement) {
            return false;
        }

        foreach ($clone->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature') as $node) {
            if (!$node->parentNode instanceof DOMNode) {
                continue;
            }

            $node->parentNode->removeChild($node);
        }

        if (!$reference->ownerDocument instanceof DOMDocument) {
            return false;
        }

        $xpath = $this->createXPath($reference->ownerDocument);
        $digestMethod = $this->stringValue($xpath, 'string(./ds:DigestMethod/@Algorithm)', $reference);
        $digestValue = $this->stringValue($xpath, 'string(./ds:DigestValue)', $reference);
        $transformAlgorithm = $this->resolveCanonicalizationTransform($reference);
        $canonicalized = $this->canonicalizeNode($clone, $transformAlgorithm);

        if ($canonicalized === null || $digestValue === '') {
            return false;
        }

        return hash_equals($digestValue, base64_encode(hash($this->resolveDigestAlgorithm($digestMethod), $canonicalized, true)));
    }

    private function resolveCanonicalizationTransform(DOMElement $reference): string
    {
        if (!$reference->ownerDocument instanceof DOMDocument) {
            return 'http://www.w3.org/2001/10/xml-exc-c14n#';
        }

        $xpath = $this->createXPath($reference->ownerDocument);
        $transforms = $xpath->query('./ds:Transforms/ds:Transform/@Algorithm', $reference);

        if (!$transforms instanceof DOMNodeList || $transforms->length === 0) {
            return 'http://www.w3.org/2001/10/xml-exc-c14n#';
        }

        foreach ($transforms as $transform) {
            if (!$transform instanceof DOMNode) {
                continue;
            }

            $algorithm = mb_trim((string) $transform->nodeValue);

            if (in_array($algorithm, [
                'http://www.w3.org/2001/10/xml-exc-c14n#',
                'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
                'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments',
            ], true)) {
                return $algorithm;
            }
        }

        return 'http://www.w3.org/2001/10/xml-exc-c14n#';
    }

    private function assertResponseBoundToRequest(DOMXPath $xpath, string $requestId): void
    {
        $inResponseTo = $this->firstAttributeValue(
            $xpath,
            [
                '(//saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@InResponseTo)[1]',
                '(//samlp:Response/@InResponseTo)[1]',
            ],
        );

        if ($inResponseTo === '' || $inResponseTo !== $requestId) {
            throw InvalidSamlRequestBindingException::create();
        }
    }

    private function assertDestinationMatches(SsoProviderRecord $provider, DOMXPath $xpath): void
    {
        $destination = $this->stringValue($xpath, 'string((/samlp:Response/@Destination)[1])');

        if ($destination === '') {
            return;
        }

        $expectedDestination = $this->callbackUrl($provider);

        if ($destination !== $expectedDestination) {
            throw InvalidSamlDestinationException::create();
        }
    }

    private function assertRecipientMatches(SsoProviderRecord $provider, DOMXPath $xpath): void
    {
        $recipient = $this->firstAttributeValue($xpath, [
            '(//saml:SubjectConfirmationData/@Recipient)[1]',
        ]);

        if ($recipient === '') {
            return;
        }

        $expectedRecipient = $this->callbackUrl($provider);

        if ($recipient !== $expectedRecipient) {
            throw InvalidSamlRecipientException::create();
        }
    }

    private function resolveIssuer(DOMXPath $xpath): string
    {
        return $this->firstStringValue($xpath, [
            'string((//saml:Assertion/saml:Issuer)[1])',
            'string((//samlp:Response/saml:Issuer)[1])',
        ]);
    }

    private function resolveExpectedIssuer(SsoProviderRecord $provider): ?string
    {
        if ($provider->validIssuer !== null && $provider->validIssuer !== '') {
            return $provider->validIssuer;
        }

        $metadata = $this->resolveMetadata($provider);

        return $metadata['entity_id'] ?? null;
    }

    private function assertTemporalConditions(DOMXPath $xpath): void
    {
        $now = CarbonImmutable::now();

        $notBefore = $this->parseDateTime($this->firstAttributeValue($xpath, [
            '(//saml:Assertion/saml:Conditions/@NotBefore)[1]',
        ]));
        $notOnOrAfter = $this->parseDateTime($this->firstAttributeValue($xpath, [
            '(//saml:Assertion/saml:Conditions/@NotOnOrAfter)[1]',
            '(//saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter)[1]',
        ]));

        if ($notBefore instanceof DateTimeImmutable && $notBefore > $now) {
            throw SamlAssertionNotYetValidException::create();
        }

        if ($notOnOrAfter instanceof DateTimeImmutable && $notOnOrAfter <= $now) {
            throw ExpiredSamlAssertionException::create();
        }
    }

    private function assertAudienceMatches(SsoProviderRecord $provider, DOMXPath $xpath): void
    {
        $audienceValues = $xpath->query('//saml:Audience');

        if (!$audienceValues instanceof DOMNodeList || $audienceValues->length === 0) {
            return;
        }

        foreach ($audienceValues as $audienceValue) {
            if ($audienceValue instanceof DOMNode && mb_trim($audienceValue->textContent) === $provider->clientId) {
                return;
            }
        }

        throw InvalidSamlAudienceException::create();
    }

    /**
     * @param array<string, mixed> $attributes
     */
    private function resolveEmail(SsoProviderRecord $provider, DOMXPath $xpath, array $attributes): ?string
    {
        $configuredAttribute = Arr::get($provider->settingsMap(), 'email_attribute');
        $candidateNames = array_filter([
            is_string($configuredAttribute) ? $configuredAttribute : null,
            'email',
            'mail',
            'emailaddress',
            'preferred_username',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
            'urn:oid:0.9.2342.19200300.100.1.3',
        ]);

        foreach ($candidateNames as $candidateName) {
            $value = $attributes[$candidateName] ?? null;

            if (is_string($value) && $value !== '') {
                return Str::lower($value);
            }

            if (is_array($value) && is_string($value[0] ?? null) && $value[0] !== '') {
                return Str::lower($value[0]);
            }
        }

        $nameId = $this->stringValue($xpath, 'string((//saml:Assertion/saml:Subject/saml:NameID)[1])');

        return filter_var($nameId, FILTER_VALIDATE_EMAIL) !== false
            ? Str::lower($nameId)
            : null;
    }

    /**
     * @return array<string, mixed>
     */
    private function resolveAttributes(DOMXPath $xpath): array
    {
        $attributes = [];
        $nodes = $xpath->query('//saml:Attribute');

        if (!$nodes instanceof DOMNodeList) {
            return $attributes;
        }

        foreach ($nodes as $node) {
            if (!$node instanceof DOMElement) {
                continue;
            }

            $key = $node->getAttribute('Name') ?: $node->getAttribute('FriendlyName');

            if ($key === '') {
                continue;
            }

            $values = [];

            $valueNodes = $xpath->query('saml:AttributeValue', $node);

            if (!$valueNodes instanceof DOMNodeList) {
                continue;
            }

            foreach ($valueNodes as $attributeValueNode) {
                if (!$attributeValueNode instanceof DOMNode) {
                    continue;
                }

                $value = mb_trim($attributeValueNode->textContent);

                if ($value === '') {
                    continue;
                }

                $values[] = $value;
            }

            if ($values === []) {
                continue;
            }

            $attributes[$key] = count($values) === 1 ? $values[0] : $values;
        }

        return $attributes;
    }

    /**
     * @return array<int, string>
     */
    private function resolveTrustedCertificates(SsoProviderRecord $provider): array
    {
        $settings = $provider->settingsMap();
        $certificates = collect(Arr::wrap(Arr::get($settings, 'x509_certificates', [])))
            ->push(Arr::get($settings, 'x509_certificate'))
            ->map(function (mixed $certificate): string {
                if (!is_string($certificate) || mb_trim($certificate) === '') {
                    return '';
                }

                return $this->normalizeCertificate($certificate);
            })
            ->filter()
            ->values();

        $metadata = $this->resolveMetadata($provider);

        return $certificates
            ->merge(collect($metadata['certificates'])
                ->map(fn (string $certificate): string => $this->normalizeCertificate($certificate)))
            ->unique()
            ->values()
            ->all();
    }

    /**
     * @return array{certificates: array<int, string>, entity_id: null|string, sso_url: null|string}
     */
    private function resolveMetadata(SsoProviderRecord $provider): array
    {
        $metadataUrl = Arr::get($provider->settingsMap(), 'metadata_url');

        if (!is_string($metadataUrl) || $metadataUrl === '') {
            return [
                'certificates' => [],
                'entity_id' => null,
                'sso_url' => null,
            ];
        }

        $metadata = Cache::remember(
            'sso:saml:metadata:'.$provider->id.':'.sha1($metadataUrl),
            now()->addSeconds(Configuration::cache()->metadataTtl()),
            function () use ($metadataUrl): array {
                $response = $this->http->accept('application/samlmetadata+xml, application/xml, text/xml')
                    ->get($metadataUrl)
                    ->throw();

                return $this->parseMetadata($response->body());
            },
        );

        if (!is_array($metadata)) {
            throw InvalidSamlMetadataXmlException::create();
        }

        /** @var array{certificates: array<int, string>, entity_id: null|string, sso_url: null|string} $metadata */
        return $metadata;
    }

    /**
     * @return array{certificates: array<int, string>, entity_id: null|string, sso_url: null|string}
     */
    private function parseMetadata(string $xml): array
    {
        $document = new DOMDocument();

        if ($document->loadXML($xml, LIBXML_NONET | LIBXML_NOBLANKS | LIBXML_NOCDATA) === false) {
            throw InvalidSamlMetadataXmlException::create();
        }

        $xpath = $this->createXPath($document);
        $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');

        $certificates = [];
        $certificateNodes = $xpath->query('//md:IDPSSODescriptor/md:KeyDescriptor[not(@use) or @use="signing"]//ds:X509Certificate');

        if ($certificateNodes instanceof DOMNodeList) {
            foreach ($certificateNodes as $certificateNode) {
                if (!$certificateNode instanceof DOMNode) {
                    continue;
                }

                $certificate = mb_trim($certificateNode->textContent);

                if ($certificate === '') {
                    continue;
                }

                $certificates[] = $certificate;
            }
        }

        return [
            'certificates' => $certificates,
            'entity_id' => $this->firstStringValue($xpath, [
                'string((/md:EntityDescriptor/@entityID)[1])',
                'string((//md:EntityDescriptor/@entityID)[1])',
            ]),
            'sso_url' => $this->firstStringValue($xpath, [
                'string((//md:IDPSSODescriptor/md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location)[1])',
                'string((//md:IDPSSODescriptor/md:SingleSignOnService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"]/@Location)[1])',
                'string((//md:IDPSSODescriptor/md:SingleSignOnService/@Location)[1])',
            ]),
        ];
    }

    private function normalizeCertificate(string $certificate): string
    {
        $certificate = mb_trim($certificate);

        if ($certificate === '') {
            return '';
        }

        if (Str::contains($certificate, 'BEGIN CERTIFICATE')) {
            return $certificate;
        }

        $wrapped = mb_trim(chunk_split(preg_replace('/\s+/', '', $certificate) ?: '', 64, "\n"));

        return "-----BEGIN CERTIFICATE-----\n{$wrapped}\n-----END CERTIFICATE-----";
    }

    private function metadataCacheKey(SsoProviderRecord $provider): ?string
    {
        $metadataUrl = Arr::get($provider->settingsMap(), 'metadata_url');

        if (!is_string($metadataUrl) || $metadataUrl === '') {
            return null;
        }

        return 'sso:saml:metadata:'.$provider->id.':'.sha1($metadataUrl);
    }

    private function resolveSignatureAlgorithm(string $algorithm): int
    {
        return match ($algorithm) {
            'http://www.w3.org/2000/09/xmldsig#rsa-sha1' => OPENSSL_ALGO_SHA1,
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384' => OPENSSL_ALGO_SHA384,
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' => OPENSSL_ALGO_SHA512,
            default => OPENSSL_ALGO_SHA256,
        };
    }

    private function resolveDigestAlgorithm(string $algorithm): string
    {
        return match ($algorithm) {
            'http://www.w3.org/2000/09/xmldsig#sha1' => 'sha1',
            'http://www.w3.org/2001/04/xmldsig-more#sha384' => 'sha384',
            'http://www.w3.org/2001/04/xmlenc#sha512' => 'sha512',
            default => 'sha256',
        };
    }

    private function canonicalizeNode(DOMNode $node, string $algorithm): ?string
    {
        if ($node instanceof DOMElement && $node->parentNode === null) {
            $document = new DOMDocument('1.0', 'UTF-8');
            $importedNode = $document->importNode($node, true);

            if (!$importedNode instanceof DOMElement) {
                return null;
            }

            $document->appendChild($importedNode);
            $node = $document->documentElement;

            if (!$node instanceof DOMElement) {
                return null;
            }
        }

        $exclusive = !str_contains($algorithm, '20010315');
        $withComments = str_ends_with($algorithm, '#WithComments');
        $canonicalized = $node->C14N($exclusive, $withComments);

        return is_string($canonicalized) && $canonicalized !== '' ? $canonicalized : null;
    }

    /**
     * @param array<int, string> $expressions
     */
    private function firstAttributeValue(DOMXPath $xpath, array $expressions): string
    {
        foreach ($expressions as $expression) {
            $value = $this->stringValue($xpath, sprintf('string(%s)', $expression));

            if ($value !== '') {
                return $value;
            }
        }

        return '';
    }

    /**
     * @param array<int, string> $expressions
     */
    private function firstStringValue(DOMXPath $xpath, array $expressions): string
    {
        foreach ($expressions as $expression) {
            $value = $this->stringValue($xpath, $expression);

            if ($value !== '') {
                return $value;
            }
        }

        return '';
    }

    private function stringValue(DOMXPath $xpath, string $expression, ?DOMNode $contextNode = null): string
    {
        $value = $xpath->evaluate($expression, $contextNode);

        return is_string($value) ? mb_trim($value) : '';
    }

    private function parseDateTime(string $value): ?DateTimeImmutable
    {
        if ($value === '') {
            return null;
        }

        return new DateTimeImmutable($value);
    }

    private function createXPath(DOMDocument $document): DOMXPath
    {
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
        $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');

        return $xpath;
    }

    /**
     * @param array<string, mixed> $settings
     */
    private function settingString(array $settings, string $key, string $default): string
    {
        $value = Arr::get($settings, $key, $default);

        return is_string($value) && $value !== '' ? $value : $default;
    }

    private function callbackUrl(SsoProviderRecord $provider): string
    {
        $routeName = Configuration::routes()->callbackName();

        return route($routeName, [
            'scheme' => $provider->scheme,
        ], true);
    }
}
