<?php

declare(strict_types=1);

/**
 * Type aliases read from the installed AWS SDK's service model, so PHPStan checks against the same
 * values the SDK does rather than a copy of them.
 */

$data = __DIR__ . '/vendor/aws/aws-sdk-php/src/data';
$manifest = require $data . '/manifest.json.php';
$api = require sprintf('%s/cognito-idp/%s/api-2.json.php', $data, $manifest['cognito-idp']['versions']['latest']);

$input = $api['operations']['AdminRespondToAuthChallenge']['input']['shape'];
$challengeNameShape = $api['shapes'][$input]['members']['ChallengeName']['shape'];

return [
    'parameters' => [
        'typeAliases' => [
            'CognitoChallengeName' => implode('|', array_map(
                static fn (string $name): string => var_export($name, true),
                $api['shapes'][$challengeNameShape]['enum'],
            )),
        ],
    ],
];
