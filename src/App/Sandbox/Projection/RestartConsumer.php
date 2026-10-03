<?php

declare(strict_types=1);

namespace Funnypot\App\Sandbox\Projection;

enum RestartConsumer: string
{
    case PREPARE = 'prepare';
    case EDGE = 'edge';
    case WEB = 'web';
    case PROTOCOLS = 'protocols';
    case WORKER = 'worker';
    case EGRESS = 'egress';
    case POST_EXPLOIT_STATE = 'post-exploit-state';
    case UPLOAD_SAMPLE = 'upload-sample';
}
