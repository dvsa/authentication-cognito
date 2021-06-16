<?php

namespace Dvsa\Authentication\Cognito;

use Dvsa\Contracts\Auth\AccessTokenInterface;
use League\OAuth2\Client\Token\AccessToken as BaseAccessToken;

/**
 * An extension to the AccessToken class to include an OIDC ID token.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html
 *
 * @psalm-suppress PropertyNotSetInConstructor
 */
class AccessToken extends BaseAccessToken implements AccessTokenInterface
{
    /**
     * @var null|string
     */
    protected $idToken;

    /**
     * @inheritDoc
     */
    public function __construct(array $options = [])
    {
        parent::__construct($options);

        if (!empty($this->values['id_token'])) {
            $this->idToken = $this->values['id_token'];

            unset($this->values['id_token']);
        }
    }

    public function getIdToken(): ?string
    {
        return $this->idToken;
    }

    /**
     * @inheritdoc
     */
    public function jsonSerialize(): array
    {
        $parameters = parent::jsonSerialize();

        if ($this->idToken) {
            $parameters['id_token'] = $this->idToken;
        }

        return $parameters;
    }

    public static function create(array $result): self
    {
        $options = [];

        $options['access_token'] = $result['AccessToken'];
        $options['id_token'] = $result['IdToken'];
        $options['refresh_token'] = $result['RefreshToken'];
        $options['expires_in'] = $result['ExpiresIn'];
        $options['token_type'] = $result['TokenType'];

        return new self($options);
    }
}
