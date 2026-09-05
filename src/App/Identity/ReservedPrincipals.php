<?php

declare(strict_types=1);

namespace Funnypot\App\Identity;

/**
 * The OS principals reserved for the future post-exploit state service and upload-sample role.
 * This code creates no account; it only refuses to prepare an identity on a host where one of the
 * reserved names or numeric ids already exists with a DIFFERENT shape (a foreign uid squatting on
 * 10005 would later be able to read the state role's materialized key). Complete absence is valid,
 * a complete exact match is valid, anything partial or conflicting fails closed.
 */
final class ReservedPrincipals
{
    /** @var array<string,array{name:string,uid:int,gid:int,dir:string,shell:string}> */
    public const TUPLES = [
        'post-exploit-state' => ['name' => 'funnypot-state', 'uid' => 10005, 'gid' => 10005, 'dir' => '/nonexistent', 'shell' => '/usr/sbin/nologin'],
        'upload-sample' => ['name' => 'funnypot-sample', 'uid' => 10006, 'gid' => 10006, 'dir' => '/nonexistent', 'shell' => '/usr/sbin/nologin'],
    ];

    public function __construct(private IdentityFileOps $ops)
    {
    }

    public function verify(): void
    {
        foreach (self::TUPLES as $t) {
            $pwName = $this->ops->passwdByName($t['name']);
            $pwUid = $this->ops->passwdByUid($t['uid']);
            $grName = $this->ops->groupByName($t['name']);
            $grGid = $this->ops->groupByGid($t['gid']);
            if ($pwName === null && $pwUid === null && $grName === null && $grGid === null) {
                continue; // not provisioned yet — valid at this stage
            }
            if ($pwName === null || $pwUid === null || $grName === null || $grGid === null) {
                throw IdentityBootstrapException::withCode('reserved-principal-partial', IdentityBootstrapException::REMEDY_ACCOUNTS);
            }
            foreach ([$pwName, $pwUid] as $pw) {
                if (($pw['name'] ?? null) !== $t['name']
                    || (int) ($pw['uid'] ?? -1) !== $t['uid']
                    || (int) ($pw['gid'] ?? -1) !== $t['gid']
                    || ($pw['dir'] ?? null) !== $t['dir']
                    || ($pw['shell'] ?? null) !== $t['shell']) {
                    throw IdentityBootstrapException::withCode('reserved-principal-conflict', IdentityBootstrapException::REMEDY_ACCOUNTS);
                }
            }
            foreach ([$grName, $grGid] as $gr) {
                $members = $gr['members'] ?? null;
                if (($gr['name'] ?? null) !== $t['name']
                    || (int) ($gr['gid'] ?? -1) !== $t['gid']
                    || !is_array($members) || $members !== []) {
                    throw IdentityBootstrapException::withCode('reserved-principal-conflict', IdentityBootstrapException::REMEDY_ACCOUNTS);
                }
            }
        }
    }
}
