<?php

declare(strict_types=1);

return [
    'schema' => 'funnypot-runtime-roles/v1',
    'roles' => [
        ['role_id' => 'prepare', 'uid' => 0, 'gid' => 0, 'supplemental_gids' => [], 'long_lived' => false],
        ['role_id' => 'edge', 'uid' => 10001, 'gid' => 10001, 'supplemental_gids' => [], 'long_lived' => true],
        ['role_id' => 'web', 'uid' => 10007, 'gid' => 10007, 'supplemental_gids' => [10000], 'long_lived' => true],
        ['role_id' => 'protocols', 'uid' => 10002, 'gid' => 10002, 'supplemental_gids' => [10000], 'long_lived' => true],
        ['role_id' => 'worker', 'uid' => 10003, 'gid' => 10003, 'supplemental_gids' => [10000], 'long_lived' => true],
        ['role_id' => 'egress', 'uid' => 10004, 'gid' => 10004, 'supplemental_gids' => [], 'long_lived' => true],
    ],
];
