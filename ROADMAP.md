# funnypot (app) — housekeeping notes

## Digital Asset Reserve — embedded ETH addresses are REAL (operational debt, flagged on purpose)

`src/App/Render/Fake/Bank.php` (`Bank::ETH_RESERVE`) embeds 4 **real, currently-funded Ethereum
addresses** as the "Digital Asset Reserve" crypto-treasury lure (`/{mount}/bank/crypto`):

- `0x638A2f4c652DcdD671Adc9b712e0DaBF01E256C5`
- `0x68C936f2A0EdEd3c28293af9BEdD2E01D4A4c95C`
- `0xFc8bD5408d04Cd82465F929d37d8279f464e8D8F`
- `0x27684c1938239e09bC74c607ceCa0C718dedcaC6`

They're used ONLY as a deliberately-inert "greed lure" — the honeypot never holds or derives their
private keys (the `demo/decoys/wallet.json` keystore decoy built by `scripts/build-decoys.sh` carries
NONSENSE ciphertext/mac on purpose), so funds can never move through this app. The displayed balances
(~500 ETH each, ~2000 ETH / ~$4.9M total) are a **point-in-time snapshot as of 2026-08-24** and will
drift as the real chain moves.

**Action needed periodically:** re-verify each address is still funded, and swap out any that empties.
Source data + the exact re-check method (a plain `eth_getBalance` JSON-RPC call, no API key needed) live
in `funnypot-project/scratchpad/crypto-addresses.md` (session-scoped scratch — if that file is gone,
the method is: `curl -s -X POST https://ethereum.publicnode.com -H 'Content-Type: application/json' -d
'{"jsonrpc":"2.0","method":"eth_getBalance","params":["<address>","latest"],"id":1}'` — a `"0x0"` or
near-zero result means drained; drop/replace that address in `Bank::ETH_RESERVE`). No automated job
does this yet — tracked here as intentional operational debt until one exists.
