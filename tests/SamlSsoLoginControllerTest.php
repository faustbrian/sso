<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\SSO\Models\SsoProvider;
use Illuminate\Support\Facades\Http;
use Tests\Exceptions\MissingSamlElementIdException;
use Tests\Exceptions\MissingSamlResponseElementException;
use Tests\Exceptions\UnableToBuildUnsignedSamlResponseFixtureException;
use Tests\Exceptions\UnableToCanonicalizeSamlSignedInfoException;
use Tests\Exceptions\UnableToGenerateSamlPrivateKeyException;
use Tests\Exceptions\UnableToGenerateSamlSigningCertificateRequestException;
use Tests\Exceptions\UnableToSelfSignSamlCertificateException;
use Tests\Exceptions\UnableToSignSamlResponseException;
use Tests\Fixtures\TestUser;

it('redirects to the provider authorization endpoint for saml providers', function (): void {
    $provider = createSamlProvider();

    $response = $this->get('/sso/'.$provider->scheme.'/redirect');

    $response->assertRedirect();
    expect($response->headers->get('Location'))->toContain('https://idp.example.test/sso')
        ->and($response->headers->get('Location'))->toContain('SAMLRequest=')
        ->and($response->headers->get('Location'))->toContain('RelayState=')
        ->and(session()->has('sso.'.$provider->scheme))->toBeTrue();
});

it('can accept an unsigned saml response when explicitly allowed', function (): void {
    $provider = createSamlProvider([
        'require_signature' => false,
    ]);
    $user = TestUser::query()->create([
        'email' => 'saml.user@example.test',
        'name' => 'Saml User',
        'password' => 'secret',
    ]);

    $this->withSession([
        'sso.'.$provider->scheme => [
            'state' => 'test-state',
            'nonce' => 'request-id-123',
        ],
    ]);

    $this->post('/sso/'.$provider->scheme.'/callback', [
        'RelayState' => 'test-state',
        'SAMLResponse' => createSamlResponse(
            issuer: 'https://idp.example.test/entity',
            requestId: 'request-id-123',
            email: $user->email,
            subject: 'saml-subject-1',
            recipient: route('sso.callback', ['scheme' => $provider->scheme]),
        ),
    ])->assertRedirect('/');

    $this->assertAuthenticatedAs($user);
});

it('requires a signed saml response by default', function (): void {
    $provider = createSamlProvider();

    $this->withSession([
        'sso.'.$provider->scheme => [
            'state' => 'test-state',
            'nonce' => 'request-id-123',
        ],
    ]);

    $this->post('/sso/'.$provider->scheme.'/callback', [
        'RelayState' => 'test-state',
        'SAMLResponse' => createSamlResponse(
            issuer: 'https://idp.example.test/entity',
            requestId: 'request-id-123',
            email: 'unsigned@example.test',
            subject: 'unsigned-subject',
            recipient: route('sso.callback', ['scheme' => $provider->scheme]),
        ),
    ])
        ->assertRedirect('/sso')
        ->assertSessionHasErrors('sso');
});

it('logs in a user from a signed saml response', function (): void {
    [$privateKey, $certificate] = createSamlCertificate();
    $provider = createSamlProvider([
        'x509_certificates' => [$certificate],
    ]);
    $user = TestUser::query()->create([
        'email' => 'signed.saml.user@example.test',
        'name' => 'Signed Saml User',
        'password' => 'secret',
    ]);

    $this->withSession([
        'sso.'.$provider->scheme => [
            'state' => 'test-state',
            'nonce' => 'request-id-123',
        ],
    ]);

    $this->post('/sso/'.$provider->scheme.'/callback', [
        'RelayState' => 'test-state',
        'SAMLResponse' => createSignedSamlResponse(
            privateKey: $privateKey,
            issuer: 'https://idp.example.test/entity',
            requestId: 'request-id-123',
            email: $user->email,
            subject: 'signed-saml-subject-1',
            recipient: route('sso.callback', ['scheme' => $provider->scheme]),
        ),
    ])->assertRedirect('/');

    $this->assertAuthenticatedAs($user);
});

it('can load saml signing certificates from metadata', function (): void {
    [$privateKey, $certificate] = createSamlCertificate();
    $provider = createSamlProvider([
        'metadata_url' => 'https://idp.example.test/metadata',
    ]);
    $user = TestUser::query()->create([
        'email' => 'metadata.saml.user@example.test',
        'name' => 'Metadata Saml User',
        'password' => 'secret',
    ]);

    Http::fake([
        'https://idp.example.test/metadata' => Http::response(createSamlMetadata($certificate), 200, [
            'Content-Type' => 'application/samlmetadata+xml',
        ]),
    ]);

    $this->withSession([
        'sso.'.$provider->scheme => [
            'state' => 'test-state',
            'nonce' => 'request-id-123',
        ],
    ]);

    $this->post('/sso/'.$provider->scheme.'/callback', [
        'RelayState' => 'test-state',
        'SAMLResponse' => createSignedSamlResponse(
            privateKey: $privateKey,
            issuer: 'https://idp.example.test/entity',
            requestId: 'request-id-123',
            email: $user->email,
            subject: 'signed-saml-subject-metadata',
            recipient: route('sso.callback', ['scheme' => $provider->scheme]),
        ),
    ])->assertRedirect('/');

    $this->assertAuthenticatedAs($user);
});

it('signs saml authn requests when the provider requires it', function (): void {
    [$privateKey] = createSamlCertificate();
    $provider = createSamlProvider([
        'sign_authn_request' => true,
    ], clientSecret: $privateKey);

    $response = $this->get('/sso/'.$provider->scheme.'/redirect');

    $response->assertRedirect();
    expect($response->headers->get('Location'))->toContain('Signature=')
        ->and($response->headers->get('Location'))->toContain('SigAlg=');
});

function createSamlProvider(array $settings = [], string $clientSecret = ''): SsoProvider
{
    $count = SsoProvider::query()->count() + 1;

    return SsoProvider::query()->create([
        'tenant_id' => TestUser::query()->create([
            'email' => 'saml-org-'.$count.'@example.test',
            'name' => 'Saml Tenant',
            'password' => 'secret',
        ])->id,
        'id' => 'saml-provider-'.$count,
        'driver' => 'saml2',
        'scheme' => 'saml-acme-'.$count,
        'display_name' => 'Acme SAML',
        'authority' => 'https://idp.example.test/sso',
        'client_id' => 'https://sp.example.test/metadata',
        'client_secret' => $clientSecret,
        'valid_issuer' => 'https://idp.example.test/entity',
        'validate_issuer' => true,
        'enabled' => true,
        'settings' => array_replace([
            'email_attribute' => 'email',
        ], $settings),
    ]);
}

function createSamlCertificate(): array
{
    $privateKeyResource = openssl_pkey_new([
        'private_key_bits' => 2_048,
        'private_key_type' => \OPENSSL_KEYTYPE_RSA,
    ]);

    if ($privateKeyResource === false) {
        throw UnableToGenerateSamlPrivateKeyException::create();
    }

    $distinguishedName = [
        'commonName' => 'saml-idp.example.test',
        'organizationName' => 'Shipit Test IdP',
        'countryName' => 'FI',
    ];

    $certificateSigningRequest = openssl_csr_new($distinguishedName, $privateKeyResource, [
        'digest_alg' => 'sha256',
    ]);

    if ($certificateSigningRequest === false) {
        throw UnableToGenerateSamlSigningCertificateRequestException::create();
    }

    $certificateResource = openssl_csr_sign($certificateSigningRequest, null, $privateKeyResource, 365, [
        'digest_alg' => 'sha256',
    ]);

    if ($certificateResource === false) {
        throw UnableToSelfSignSamlCertificateException::create();
    }

    openssl_pkey_export($privateKeyResource, $privateKey);
    openssl_x509_export($certificateResource, $certificate);

    return [$privateKey, $certificate];
}

function createSamlResponse(string $issuer, string $requestId, string $email, string $subject, string $recipient): string
{
    $issuedAt = now()->toIso8601String();
    $notBefore = now()->subMinute()->toIso8601String();
    $notOnOrAfter = now()->addHour()->toIso8601String();

    $xml = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response_1" Version="2.0" IssueInstant="{$issuedAt}" InResponseTo="{$requestId}" Destination="{$recipient}">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{$issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
  </samlp:Status>
  <saml:Assertion ID="_assertion_1" IssueInstant="{$issuedAt}" Version="2.0">
    <saml:Issuer>{$issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID>{$subject}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="{$requestId}" NotOnOrAfter="{$notOnOrAfter}" Recipient="{$recipient}" />
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{$notBefore}" NotOnOrAfter="{$notOnOrAfter}" />
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>{$email}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
XML;

    return base64_encode($xml);
}

function createSignedSamlResponse(string $privateKey, string $issuer, string $requestId, string $email, string $subject, string $recipient): string
{
    $xml = base64_decode(createSamlResponse(
        issuer: $issuer,
        requestId: $requestId,
        email: $email,
        subject: $subject,
        recipient: $recipient,
    ), true);

    if (!is_string($xml) || $xml === '') {
        throw UnableToBuildUnsignedSamlResponseFixtureException::create();
    }

    $document = new DOMDocument();
    $document->loadXML($xml, \LIBXML_NOBLANKS | \LIBXML_NOCDATA | \LIBXML_NONET);

    $xpath = new DOMXPath($document);
    $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');

    $response = $xpath->query('/samlp:Response')->item(0);

    if (!$response instanceof DOMElement) {
        throw MissingSamlResponseElementException::create();
    }

    signSamlElement($document, $response, $privateKey);

    return base64_encode($document->saveXML() ?: '');
}

function createSamlMetadata(string $certificate): string
{
    $encodedCertificate = mb_trim(str_replace([
        '-----BEGIN CERTIFICATE-----',
        '-----END CERTIFICATE-----',
        "\r",
        "\n",
    ], '', $certificate));

    return <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test/entity">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>{$encodedCertificate}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
XML;
}

function signSamlElement(DOMDocument $document, DOMElement $element, string $privateKey): void
{
    $xmlDsSignatureNamespace = 'http://www.w3.org/2000/09/xmldsig#';
    $elementId = $element->getAttribute('ID');

    if ($elementId === '') {
        throw MissingSamlElementIdException::create();
    }

    $signature = $document->createElementNS($xmlDsSignatureNamespace, 'ds:Signature');
    $signedInfo = $document->createElementNS($xmlDsSignatureNamespace, 'ds:SignedInfo');
    $canonicalizationMethod = $document->createElementNS($xmlDsSignatureNamespace, 'ds:CanonicalizationMethod');
    $canonicalizationMethod->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');

    $signatureMethod = $document->createElementNS($xmlDsSignatureNamespace, 'ds:SignatureMethod');
    $signatureMethod->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');

    $reference = $document->createElementNS($xmlDsSignatureNamespace, 'ds:Reference');
    $reference->setAttribute('URI', '#'.$elementId);

    $transforms = $document->createElementNS($xmlDsSignatureNamespace, 'ds:Transforms');
    $envelopedTransform = $document->createElementNS($xmlDsSignatureNamespace, 'ds:Transform');
    $envelopedTransform->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature');

    $exclusiveTransform = $document->createElementNS($xmlDsSignatureNamespace, 'ds:Transform');
    $exclusiveTransform->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');

    $digestMethod = $document->createElementNS($xmlDsSignatureNamespace, 'ds:DigestMethod');
    $digestMethod->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');

    $transforms->appendChild($envelopedTransform);
    $transforms->appendChild($exclusiveTransform);

    $reference->appendChild($transforms);
    $reference->appendChild($digestMethod);
    $reference->appendChild($document->createElementNS(
        $xmlDsSignatureNamespace,
        'ds:DigestValue',
        base64_encode(hash('sha256', $element->C14N(true, false), true)),
    ));
    $signedInfo->appendChild($canonicalizationMethod);
    $signedInfo->appendChild($signatureMethod);
    $signedInfo->appendChild($reference);

    $signature->appendChild($signedInfo);

    $issuerNodes = $element->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer');
    $issuerNode = $issuerNodes->item(0);

    if ($issuerNode instanceof DOMElement && $issuerNode->parentNode === $element) {
        $element->insertBefore($signature, $issuerNode->nextSibling);
    } else {
        $element->insertBefore($signature, $element->firstChild);
    }

    $canonicalSignedInfo = $signedInfo->C14N(true, false);

    if ($canonicalSignedInfo === false) {
        throw UnableToCanonicalizeSamlSignedInfoException::create();
    }

    $signed = openssl_sign($canonicalSignedInfo, $signatureValue, $privateKey, \OPENSSL_ALGO_SHA256);

    if (!$signed) {
        throw UnableToSignSamlResponseException::create();
    }

    $signature->appendChild($document->createElementNS(
        $xmlDsSignatureNamespace,
        'ds:SignatureValue',
        base64_encode((string) $signatureValue),
    ));
}
