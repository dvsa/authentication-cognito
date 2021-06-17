<?php

namespace Dvsa\Authentication\Cognito\Tests;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Credentials\Credentials;
use Aws\MockHandler;
use Aws\Result;
use Dvsa\Authentication\Cognito\Client;
use Dvsa\Authentication\Cognito\CognitoUser;
use PHPUnit\Framework\TestCase;

class ResourceOwnerObjectReturnedFromMethodsTest extends TestCase
{
    const RESOURCE_OWNER = CognitoUser::class;

    /**
     * @var MockHandler
     */
    protected $mockHandler;

    /**
     * @var Client
     */
    protected $client;

    protected function setUp(): void
    {
        $this->mockHandler = new MockHandler();

        $awsCredentials = new Credentials('AWS_ACCESS_KEY', 'AWS_SECRET_KEY');

        $cognitoIdentityProviderClient = new CognitoIdentityProviderClient(
            [
                'credentials' => $awsCredentials,
                'region'      => 'us-west-2',
                'version'     => 'latest',
                'handler'     => $this->mockHandler
            ]
        );

        $this->client = new Client($cognitoIdentityProviderClient, 'CLIENT_ID', 'CLIENT_SECRET', 'POOL_ID');
    }

    public function testGetUserByIdentifierReturnsResourceOwnerObject(): void
    {
        $this->mockHandler->append(
            new Result(
                [
                    'Enabled' => 'true',
                    'UserAttributes' => [
                        [
                            'Name'  => 'NAME_1',
                            'Value' => 'VALUE_1',
                        ],
                        [
                            'Name'  => 'NAME_2',
                            'Value' => 'VALUE_2',
                        ],
                    ],
                    'UserCreateDate' => 'USER_CREATED_DATE',
                    'UserLastModifiedDate' => 'USER_LAST_MODIFIED_DATE',
                    'Username' => 'USERNAME',
                    'UserStatus' => 'USER_STATUS',
                ]
            )
        );

        $response = $this->client->getUserByIdentifier('IDENTIFIER');

        $this->assertInstanceOf(self::RESOURCE_OWNER, $response);

        // Assert the correct values are set on the `$response` object.
        $this->assertEquals($response->getUsername(), 'USERNAME');
        $this->assertEquals($response->enabled, 'true');
        $this->assertEquals($response->created_date, 'USER_CREATED_DATE');
        $this->assertEquals($response->last_modified_date, 'USER_LAST_MODIFIED_DATE');
        $this->assertEquals($response->status, 'USER_STATUS');
        $this->assertEquals($response->{'NAME_1'}, 'VALUE_1');
        $this->assertEquals($response->{'NAME_2'}, 'VALUE_2');
    }

    public function testRegisterReturnsResourceOwnerObject(): void
    {
        $this->mockHandler->append(
            new Result(
                [
                    'User' => [
                        'Enabled'              => 'true',
                        'Attributes'       => [
                            [
                                'Name'  => 'NAME_1',
                                'Value' => 'VALUE_1',
                            ],
                            [
                                'Name'  => 'NAME_2',
                                'Value' => 'VALUE_2',
                            ],
                        ],
                        'UserCreateDate'       => 'USER_CREATED_DATE',
                        'UserLastModifiedDate' => 'USER_LAST_MODIFIED_DATE',
                        'Username'             => 'USERNAME',
                        'UserStatus'           => 'USER_STATUS',
                    ]
                ]
            )
        );

        $response = $this->client->register('IDENTIFIER', 'PASSWORD', []);

        $this->assertInstanceOf(self::RESOURCE_OWNER, $response);

        $this->assertEquals($response->getUsername(), 'USERNAME');
        $this->assertEquals($response->enabled, 'true');
        $this->assertEquals($response->created_date, 'USER_CREATED_DATE');
        $this->assertEquals($response->last_modified_date, 'USER_LAST_MODIFIED_DATE');
        $this->assertEquals($response->status, 'USER_STATUS');
        $this->assertEquals($response->{'NAME_1'}, 'VALUE_1');
        $this->assertEquals($response->{'NAME_2'}, 'VALUE_2');
    }
}
