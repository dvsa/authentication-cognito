<?php

namespace Dvsa\Authentication\Cognito;

use Dvsa\Contracts\Auth\AbstractResourceOwner;

/**
 * A Resource owner object, containing helper methods for non-custom attributes.
 *
 * @see https://openid.net/specs/openid-connect-basic-1_0.html#rfc.section.2.5
 */
class CognitoUser extends AbstractResourceOwner
{
    public function getId(): string
    {
        return $this->get('username', $this->get('cognito:username'));
    }

    public function getAddress(): ?string
    {
        return $this->get('address');
    }

    public function getUsername(): ?string
    {
        return $this->get('username');
    }

    public function getEmail(): ?string
    {
        return $this->get('email');
    }

    public function getEmailVerified(): ?string
    {
        return $this->get('email_verified');
    }

    public function getPhoneNumber(): string
    {
        return $this->get('phone_number');
    }

    public function getPhoneNumberVerified(): ?string
    {
        return $this->get('phone_number_verified');
    }

    public function getBirthdate(): ?string
    {
        return $this->get('birthdate');
    }

    public function getProfile(): ?string
    {
        return $this->get('profile');
    }

    public function getGender(): ?string
    {
        return $this->get('gender');
    }

    public function getName(): ?string
    {
        return $this->get('name');
    }

    public function getGivenName(): ?string
    {
        return $this->get('given_name');
    }

    public function getMiddleName(): ?string
    {
        return $this->get('middle_name');
    }

    public function getFamilyName(): ?string
    {
        return $this->get('family_name');
    }

    public function getLocale(): ?string
    {
        return $this->get('locale');
    }

    public function getZoneinfo(): ?string
    {
        return $this->get('zoneinfo');
    }

    public function getPreferredUsername(): ?string
    {
        return $this->get('preferred_username');
    }

    public function getNickname(): ?string
    {
        return $this->get('nickname');
    }

    public function getWebsite(): ?string
    {
        return $this->get('website');
    }

    public function getPicture(): ?string
    {
        return $this->get('picture');
    }

    public static function prepareAwsResponse(array $result): array
    {
        $attributes = [
            'username' => $result['Username'],
            'status' => $result['UserStatus'],
            'enabled' => $result['Enabled'],
            'created_date' => $result['UserCreateDate'],
            'last_modified_date' => $result['UserLastModifiedDate'],
        ];

        // Cognito returns a slightly different structure depending on API call.
        // We will try the possible keys, and fallback to a blank array.
        $userAttributes = ($result['UserAttributes'] ?? $result['Attributes'] ?? []);

        // Attributes are in the format [['Name' => 'NAME_1', 'Value' => 'VALUE_1'], ...]
        // Convert to a ['NAME_1' => 'VALUE_1', ...] pair.
        foreach ($userAttributes as $attribute) {
            $attributes[$attribute['Name']] = $attribute['Value'];
        }

        return $attributes;
    }
}
