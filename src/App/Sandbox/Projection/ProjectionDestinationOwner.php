<?php

declare(strict_types=1);

namespace Funnypot\App\Sandbox\Projection;

enum ProjectionDestinationOwner: string
{
    case PREPARE = 'prepare';
    case EDGE = 'edge';
    case WEB = 'web';
    case PROTOCOLS = 'protocols';
    case WORKER = 'worker';
    case EGRESS = 'egress';
    case POST_EXPLOIT_STATE = 'post-exploit-state';
    case UPLOAD_SAMPLE = 'upload-sample';

    /** @return array{0:int,1:int} */
    public function ownership(): array
    {
        return match ($this) {
            self::PREPARE => [0, 0],
            self::EDGE => [10001, 10001],
            self::WEB => [10007, 10007],
            self::PROTOCOLS => [10002, 10002],
            self::WORKER => [10003, 10003],
            self::EGRESS => [10004, 10004],
            self::POST_EXPLOIT_STATE => [10005, 10005],
            self::UPLOAD_SAMPLE => [10006, 10006],
        };
    }
}
