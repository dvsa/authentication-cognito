<?php

namespace Dvsa\Authentication\Cognito\Tests;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CommandInterface;
use Aws\Credentials\Credentials;
use Aws\MockHandler;
use Aws\Result;
use Dvsa\Authentication\Cognito\Client;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Handler\MockHandler as MockHttpHandler;
use GuzzleHttp\HandlerStack;
use PHPUnit\Framework\TestCase;

class AttributesAreProvidedInCorrectFormatTest extends TestCase
{
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

        $cognitoIdentityProviderClient = new CognitoIdentityProviderClient([
            'credentials' => $awsCredentials,
            'region'  => 'us-west-2',
            'version' => 'latest',
            'handler' => $this->mockHandler
        ]);

        $handlerStack = HandlerStack::create(new MockHttpHandler());
        $httpClient = new HttpClient(['handler' => $handlerStack]);

        $this->client = new Client($cognitoIdentityProviderClient, 'CLIENT_ID', 'CLIENT_SECRET', 'POOL_ID', $httpClient);
    }

    /**
     * @dataProvider provideAttributeCombinations
     */
    public function testAttributesFormattedCorrectly(array $raw, array $expected): void
    {
        // You can provide a function to invoke; here we throw a mock exception
        $this->mockHandler->append(function (CommandInterface $cmd) use ($expected) {
            $this->assertEquals($expected, $cmd['UserAttributes']);

            return new Result();
        });

        $this->client->changeAttributes('USERNAME', $raw);
    }

    public function provideAttributeCombinations(): \Generator
    {
        yield [
            ['Key1' => 'Value1', 'Key2' => 'Value2'],
            [
                ['Name' => 'Key1', 'Value' => 'Value1'],
                ['Name' => 'Key2', 'Value' => 'Value2']
            ],
        ];

        yield [
            ['Key1' => false, 'Key2' => true],
            [
                ['Name' => 'Key1', 'Value' => 'false'],
                ['Name' => 'Key2', 'Value' => 'true']
            ],
        ];

        $date = new \DateTime();

        yield [
            ['Key1' => $date],
            [
                ['Name' => 'Key1', 'Value' => $date->format('Y-m-d H:i:s e')],
            ],
        ];

        yield [
            [],
            []
        ];
    }
}
