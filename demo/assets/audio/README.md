# SIP honeypot persona audio (drop-in)

The SIP honeypot answers a wardialer/VoIP-scanner call and plays a **persona** — a set of real
voice clips — over RTP to waste their time, recording the call. Personas are **auto-discovered**:
drop a folder of clips in here and it becomes a persona on the next server restart. No code change.

## Add a persona

1. Make a folder named for the persona: `demo/assets/audio/<name>/`
2. Put one or more **raw 8 kHz mono G.711 µ-law** clips in it, named so they sort in play order:
   `01.ulaw`, `02.ulaw`, … (`.ulaw` only; raw/headerless, the format RTP sends).
3. Restart the SIP listener. `<name>` now joins the per-caller cycle.

Convert any source audio to the right format with ffmpeg (telephone band + level match):

```bash
ffmpeg -i in.mp3 -af "highpass=f=100,lowpass=f=3400,dynaudnorm" -ar 8000 -ac 1 -f mulaw 01.ulaw
```

## Optional per-persona tuning: `persona.json`

Drop a `persona.json` in the folder to override defaults:

```json
{ "pauseSeconds": 3.5, "ringback": true, "cycle": true, "order": 10 }
```

- `pauseSeconds` — silence between clips (natural turn-taking). Default 4.0.
- `ringback` — play ~3s of ringback tone before "answering". Default true (false for `fax`).
- `cycle` — include in the per-caller auto cycle. Default true.
- `order` — cycle position; lower sorts earlier. Default 100 (then alphabetical).

## How cycling works

Auto mode deals a **different persona per call from the same IP** (call 1 → first, call 2 → next,
… then wraps). `fax` and `ring` are never in the voice cycle — they're reached by dialing `999`
(fax tone) or `888` (ringback), or by forcing `FUNNYPOT_SIP_AUDIO=<name>`.

## Licensing — why this folder's clips are gitignored

Persona clips (Lenny, scam-call recordings, movie/celebrity soundboards) are **copyright-encumbered
or non-consensual recordings** and are **not committed** (`demo/assets/audio/*/` is gitignored). Use
them on your own honeypot, but supply them at deploy — don't redistribute them in the repo.

Legally clean sources for shippable personas: **LibriVox** (public domain), **Asterisk Core Sounds**
(CC BY-SA, already µ-law), **Freesound** (CC0), or a **TTS-scripted** persona you author yourself.

## Persona provenance + license (what's dealt into the cycle)

Cycle order is set by each folder's `persona.json` `order` (lower = earlier). Current voice cycle:
`lenny → el_chango → cohen → kimble → allison → vindiesel → …` (rest default to order 100, alphabetical).

Real-recorded, cleanly-licensed additions after `lenny`:

- **el_chango** — a Córdoban/Argentine-Spanish re-recording of the Lenny concept (a rambling,
  grumbling old-timer). Real recorded voice, already 8 kHz µ-law (drop-in, no transcode).
  Source: `github.com/asternic/el_chango` — **MIT** (the cleanest license in this space).
- **cohen** — "Cohen on the Telephone" (Joe Hayman, 1913): a confused, hard-of-hearing man
  mishearing every word on a bad line — the proto-Lenny. Source: Internet Archive
  `78_cohen-on-the-telephone_joe-hayman_gbia3029365b` — **US public domain** (pre-1923). Transcoded
  from the MP3 to 8 kHz µ-law and split into ~25 s clips.

Movie/celebrity personas (real recorded voice, but **copyright-encumbered** — gitignored/local only,
your own defensive honeypot, never redistributed — same bucket as `vindiesel`/`taken`):

- **kimble** — Detective John Kimble (Arnold Schwarzenegger, *Kindergarten Cop*, 1990): 18 lines
  ("It's not a tumor", "I'm a cop you idiot, I'm Detective John Kimble", "Who is your daddy and what
  does he do", "There is no bathroom", "Stop whining"). Source: a 101soundboards board; copyrighted
  film audio + right-of-publicity. Transcoded from MP3 to 8 kHz µ-law with the telephone-band filter.

More clean sources vetted for future personas: **El Chango** (MIT), pre-1925 **78rpm comic
monologues** (archive.org George Blood collection) and the **UCSB Cylinder Audio Archive** (public
domain), **LibriVox** / **Mozilla Common Voice** / **Freesound-CC0** (all CC0/PD). Avoid Jolly Roger
(proprietary) and Kitboga (personal IP / fan-TTS).
