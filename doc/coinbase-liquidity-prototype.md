# Experimental coinbase-liquidity prototype

**EXPERIMENTAL, NOT FOR PRODUCTION FUNDS**

This is a wallet-side research prototype in `mynpub/bitcoin`, not a change to
upstream Bitcoin or to this repository's consensus rules. It does not bypass
coinbase maturity. Use disposable regtest funds first. Enabling
`-enablecoinbaseliquidityproto=1` explicitly opts into the experimental RPCs;
they are disabled by default.

## What is being financed?

The miner commits a future coinbase output to a script giving the buyer a
hashlocked claim and the miner a later recovery path. The buyer pays for that
claim through a separate HTLC. The miner spends the payment by revealing a
secret; the buyer uses the same secret to spend the financed coinbase once
consensus permits it.

**An existing coinbase output cannot be retrofitted.** Create and agree on the
offer before mining, then direct the actual coinbase output to its returned
address. The buyer must independently verify the mined outpoint before paying.
An offer alone is neither proof of mining nor proof of ownership. The amount
financed need not equal the entire block reward.

This is not a covenant, guaranteed loan, or perfectly atomic exchange. Bitcoin
Script does not make the coinbase claim conditional on the payment's continued
confirmation. A payment reorg after disclosure can leave the buyer knowing the
secret without the miner receiving final payment.

## Participants and secrets

The buyer and miner each supply a distinct compressed secp256k1 public key.
Keep the corresponding private keys in their respective wallets. The miner
generates a fresh, uniformly random **32-byte** secret offline and shares only
its SHA256 digest in the offer. Never reuse a secret across offers or protocols.
Public keys and hashes are public; private keys and unrevealed secrets are not.

Authenticate the counterparty and offer over a separate channel. Do not put a
secret in labels, logs, shell history, shared RPC traces, or an offer. Treat any
signed claim transaction, including an unbroadcast one, as disclosure: its
witness contains the secret. Anyone with access to an RPC request or response
containing the secret can learn it.

## Scripts and witnesses

Only the canonical native P2WSH template is supported. Arbitrary scripts,
P2SH wrapping, Taproot, and time-based locktimes are not interchangeable with
this protocol. The witness program is `OP_0 <SHA256(witnessScript)>`.

Both witness scripts use this ASM:

```text
OP_IF
    OP_SIZE 32 OP_EQUALVERIFY
    OP_SHA256 <secret_hash> OP_EQUALVERIFY
    <claim_pubkey> OP_CHECKSIG
OP_ELSE
    <timeout_height> OP_CHECKLOCKTIMEVERIFY OP_DROP
    <refund_pubkey> OP_CHECKSIG
OP_ENDIF
```

| Output | Claim key | Timeout key | Absolute block-height timeout |
| --- | --- | --- | --- |
| Financed coinbase | Buyer | Miner | Miner recovery height |
| Buyer payment | Miner | Buyer | Buyer refund height |

Witness examples, from bottom to top (script last):

```text
claim:    <DER_signature || SIGHASH_ALL> <32-byte secret> <01> <witnessScript>
timeout:  <DER_signature || SIGHASH_ALL> <>                  <witnessScript>
```

The false selector is an empty vector, not a one-byte zero. The true selector
is exactly `01`. Signatures commit to the spending transaction and previous
output amount. Timeout spends use a non-final input sequence and an absolute
`nLockTime` at least the timeout. Such a transaction becomes final for a block
whose height is **greater than** that locktime. Coinbase maturity independently
applies to *both* coinbase branches.

The claim branch does **not** expire at the timeout. After a timeout both
branches can be valid, producing a race. A timeout is not a mechanism for
revoking an already disclosed secret.

## Protocol state machine

The following are operational states, not a persistent wallet database or a
consensus-enforced contract:

```text
OFFER AGREED
  | mine the exact financed output at the agreed height
  v
COINBASE OBSERVED -- reorg/mismatch/missing --> STOP; do not fund
  | independently verify amount/script/height and confirmation depth
  v
BUYER PAYMENT BUILT -- not broadcast/never confirms --> ABORT
  | review, sign, broadcast, wait for confirmation depth
  v
PAYMENT CONFIRMED
  | miner rechecks BOTH outputs and remaining time, then reveals secret
  v
SECRET DISCLOSED / PAYMENT CLAIM IN FLIGHT
  | payment claim confirms                 | payment reorg/stuck
  v                                       v
MINER PAID                            ALARM; recheck and fee-bump
  | buyer waits for coinbase maturity      | secret cannot be withdrawn
  v
BUYER REDEMPTION IN FLIGHT -- reorg --> WAIT / REBUILD / FEE-BUMP
  | confirms before recovery competition
  v
COMPLETE
```

Failure and timeout branches:

* If the miner never mines the correct output, the buyer does not pay.
* If the buyer never funds, the miner waits for maturity and recovery timeout.
* If the miner does not disclose, the buyer can refund after the payment
  timeout. The miner can recover the coinbase after its separate timeout.
* If a payment or coinbase disappears, stop new financing and new disclosure.
  A disconnected transaction can return to the mempool; missing from the UTXO
  view is not proof of either successful spending or permanent loss.
* If maturity or relay rules change, stop and reassess. Do not try to bypass
  validation by constructing or broadcasting an invalid spend.
* If the secret has escaped, abort/refund is no longer risk-free. Monitor both
  outputs and competing spends until the chosen confirmation depth is reached.

## Safety and liveness assumptions

There is no custodian holding both sides' keys. Only the designated key and
secret can take a claim branch; only the timeout key can take the recovery
branch. Neither party can unilaterally spend the other's refund path.
Non-custodial **does not mean trustless or risk-free**:

* The miner must not disclose early, reuse secrets, or sign without verifying
  the buyer payment. The buyer must not fund an unverified coinbase.
* Both parties need a sufficiently accurate, fully validating chain view.
  Confirmation depth mitigates but cannot eliminate reorg risk.
* Both parties must remain online, preserve offers/keys/secrets/outpoints, and
  be able to pay prevailing fees. There is no automatic watchtower or
  transaction broadcaster.
* Enough blocks must be produced between the payment, maturity, and recovery
  boundaries. Block heights do not promise wall-clock deadlines.
* Counterparty authentication, agreement on the price, and independent
  assessment of the miner's conduct remain outside the protocol.

### Threat model

**Reorgs.** A coinbase reorg removes the financed asset; a payment-claim reorg
does not erase a publicly disclosed secret. The buyer may refund while keeping
that knowledge. Reorgs around maturity can make a previously admissible
redemption premature. The prototype rechecks chain state before building, but
no RPC response reserves a chain tip or guarantees later validity.

**Timeout races.** Claim and recovery coexist after timeout. Do not aim to
confirm in the last block. Stop revealing well before the payment refund
height, and complete redemption well before miner recovery. A pre-signed
refund does not take priority over a competing claim.

**Fees, pinning, and censorship.** A low-fee payment delays safe disclosure;
a low-fee claim can expose the secret without confirming. Replacement policy
and package relay differ between peers. RBF signaling does not guarantee
replacement acceptance; CPFP requires a spendable descendant output and fee
budget. Miner censorship or sustained congestion can defeat fixed windows.

**Rule-change and maturity-extension risk.** This fork already has a scheduled
long coinbase-maturity window. Builders must account for that existing
schedule, not simply assume 100 blocks. Future unscheduled extensions could
move maturity beyond the miner recovery height and destroy the buyer's
exclusive opportunity to redeem. No script or offer can insure against that.
Fork-specific signature rules also matter; a transaction signed for one ruleset
must not be assumed valid under another.

**Miner equivocation.** The miner can advertise incompatible offers, mine a
different script, withhold the secret, or disclose it selectively. Bind payment
to the actual canonical coinbase outpoint, script, value, and height, not an
advertisement. Distinct buyers' keys cannot both match one canonical script,
but repeated funding of the *same* offer remains an operational risk. Do not
fund an outpoint twice. There is no orderbook, anti-equivocation service,
offer signature, or economic/oracle layer.

## Operations and policy

Keep independent records of the exact offer, expected scripts, coinbase block
hash/outpoint, funding outpoint, transactions, and confirmation targets. Back
up wallet keys and the secret securely. The prototype is stateless: RPC
introspection is a current chain/mempool snapshot, not an audit log, escrow
registry, or assertion that a historical trade completed.

Use at least the enforced confirmation depth for both coinbase and payment,
and choose deeper confirmation targets for higher reorg exposure. Recheck
immediately before funding, disclosing, and redeeming. Monitor best-block
changes and both outpoints continuously; escalate on disconnects, conflicting
spends, rising mempool minimum fee, or shrinking timeout margin.

Before signing, verify every output, the fee, selected branch, previous-output
amount, locktime, and scripts. Before broadcast, use `testmempoolaccept` with
the current local policy. An accepted transaction is not a confirmation.
Keep enough separate confirmed funds for fee bumps. Review replacement
transactions manually; preserve the intended recipient and avoid accidentally
disclosing a secret during an abort. Do not rely on generic wallet fee-bumping
or generic PSBT finalization understanding an arbitrary HTLC.

Standard native P2WSH relay, active CLTV/Segwit rules, sufficient output value,
and compatible signature rules are required. Local dust, minimum relay fee,
mempool fee floor, and maximum fee checks are guardrails, not guarantees about
other peers' policies or future economic viability.

## Before any production consideration

This prototype is not suitable for production funds. Further work would
include independent cryptographic and adversarial protocol review; property
and fuzz testing of parsers, scripts, witnesses, and state transitions;
multi-node partition/deep-reorg and adversarial fee/pinning tests; explicit
hardware/external-signer support; authenticated offers and duplicate-funding
protection; durable monitoring and recovery; key/secret lifecycle review;
fee-bump/package-relay support; and analysis of every scheduled and proposed
consensus transition. These are prerequisites for further evaluation, not a
claim that production safety can be achieved.
