<?php

declare(strict_types=1);

namespace Funnypot\App\Tarpit\Ssrf;

use Funnypot\App\Render\Fake\FakeSecrets;
use Funnypot\App\Render\Fake\Fleet;
use Funnypot\App\Tarpit\ConfigDump;
use Funnypot\App\Tarpit\HostileFormat;
use Funnypot\App\Tarpit\LogRabbitHole;
use Funnypot\Shell\Fs\Draw;
use Funnypot\Shell\Fs\FakeFilesystem;

/**
 * Every key (and every settings.py host) the app's own generators serve, produced by calling those
 * generators the way their surfaces do, in bounded slices.
 *
 * Slice 0 is the small sources: the admin panel's fake secrets, the rabbit-hole log's juicy lines, the
 * hostile JSON, and the /root/.aws/credentials and /root/.env files of this box and the fleet's other
 * servers (the web console and the SSH shell build the same files). Each later slice is SLICE_SECTIONS
 * settings.py sections, up to every section the configured cap can serve. Pure: no store, no clock.
 */
final class KeyIndexBuilder
{
    public const SLICE_SECTIONS = 2048;
    public const KEY_PATTERN = '~\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\b[sr]k_(?:live|test)_[0-9A-Za-z]{10,}~';
    public const SHELL_FILES = ['/root/.aws/credentials', '/root/.env'];

    private int $sections;

    public function __construct(private int $personaSeed, private string $filesystemKey, int $capBytes)
    {
        $this->sections = Network::sections($capBytes);
    }

    public function sections(): int
    {
        return $this->sections;
    }

    public function slices(): int
    {
        return 1 + (int) ceil($this->sections / self::SLICE_SECTIONS);
    }

    /** @return list<array{0:string,1:string}> [kind, value] facts of one slice */
    public function slice(int $s): array
    {
        if ($s === 0) {
            return $this->small();
        }
        $out = [];
        $dump = new ConfigDump($this->personaSeed);
        $from = ($s - 1) * self::SLICE_SECTIONS;
        $to = min($this->sections, $from + self::SLICE_SECTIONS);
        for ($k = $from; $k < $to; $k++) {
            $f = $dump->sectionFacts($k);
            $out[] = ['aws', $f['awsKey']];
            $out[] = [(string) ServedKeys::kindOf($f['stripeKey']), $f['stripeKey']];
            $out[] = ['host', $f['svcHost']];
            $out[] = ['host', $f['cacheHost']];
        }

        return $out;
    }

    /** @return array<string,list<string>> family => keys, for the small sources */
    public function smallByFamily(): array
    {
        $fam = ['bait' => [], 'log' => [], 'hostile' => [], 'shell' => []];
        $bait = FakeSecrets::fromSeed($this->personaSeed);
        foreach ($bait->keys() as $k) {
            $fam['bait'] = [...$fam['bait'], ...self::keysIn((string) $k['fullInert'])];
        }
        foreach ($bait->envVars() as [, $v]) {
            $fam['bait'] = [...$fam['bait'], ...self::keysIn((string) $v)];
        }
        $log = new LogRabbitHole($this->personaSeed);
        foreach ($log->juicyLineIndices() as $i) {
            $fam['log'] = [...$fam['log'], ...self::keysIn($log->secretForLine($i))];
        }
        $fam['hostile'] = self::keysIn((new HostileFormat($this->personaSeed))->json(1 << 20));
        foreach (Fleet::fromSeed($this->personaSeed)->servers() as $server) {
            $seed = (int) $server['seed'];
            $fs = new FakeFilesystem(Draw::seed($this->filesystemKey . "\0" . $seed . "\0ops"), 'ops', $seed);
            foreach (self::SHELL_FILES as $file) {
                try {
                    $fam['shell'] = [...$fam['shell'], ...self::keysIn($fs->read($file))];
                } catch (\Throwable $e) {
                    // a host without the file serves no key from it
                }
            }
        }
        foreach ($fam as $f => $keys) {
            $fam[$f] = array_values(array_unique($keys));
        }

        return $fam;
    }

    /** @return list<array{0:string,1:string}> */
    private function small(): array
    {
        $out = [];
        foreach ($this->smallByFamily() as $keys) {
            foreach ($keys as $key) {
                $kind = ServedKeys::kindOf($key);
                if ($kind !== null) {
                    $out[] = [$kind, $key];
                }
            }
        }

        return $out;
    }

    /** @return list<string> */
    public static function keysIn(string $text): array
    {
        preg_match_all(self::KEY_PATTERN, $text, $m);

        return array_values(array_filter(array_unique($m[0]), static fn (string $k): bool => !ServedKeys::placeholder($k)));
    }

    /**
     * A digest of what the generators produce now: the small sources and the first two sections. A
     * generator change that alters its keys changes this, and the index rebuilds.
     */
    public function fingerprint(): string
    {
        $h = hash_init('sha256');
        foreach ($this->small() as [$kind, $value]) {
            hash_update($h, $kind . "\0" . $value . "\n");
        }
        $dump = new ConfigDump($this->personaSeed);
        for ($k = 0; $k < min(2, $this->sections); $k++) {
            hash_update($h, json_encode($dump->sectionFacts($k)) . "\n");
        }
        hash_update($h, 'sections=' . $this->sections);

        return hash_final($h);
    }
}
