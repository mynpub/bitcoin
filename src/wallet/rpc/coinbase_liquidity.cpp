// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <wallet/coinbase_liquidity.h>

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <common/sighash_rules.h>
#include <core_io.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <policy/policy.h>
#include <psbt.h>
#include <rpc/server.h>
#include <script/interpreter.h>
#include <script/sign.h>
#include <streams.h>
#include <util/rbf.h>
#include <util/strencodings.h>
#include <wallet/context.h>
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>

#include <functional>
#include <limits>
#include <stdexcept>

namespace wallet {
namespace {
using namespace liquidity;

COutPoint Outpoint(const UniValue& object)
{
    CheckFields(object, {"txid", "vout"});
    const auto& txid = object["txid"].get_str();
    if (!IsHex(txid) || txid.size() != 64) throw std::runtime_error("Invalid outpoint txid");
    const int64_t vout{object["vout"].getInt<int64_t>()};
    if (vout < 0 || vout > std::numeric_limits<uint32_t>::max()) throw std::runtime_error("Invalid outpoint vout");
    return COutPoint{Txid::FromUint256(*uint256::FromHex(txid)), static_cast<uint32_t>(vout)};
}

struct Snapshot {
    int tip;
    std::map<COutPoint, Coin> coins;
    COutPoint coinbase;
    COutPoint payment;
};

class MempoolSpends final : public interfaces::Chain::Notifications
{
    std::map<COutPoint, Coin>& m_coins;
public:
    explicit MempoolSpends(std::map<COutPoint, Coin>& coins) : m_coins{coins} {}
    void transactionAddedToMempool(const CTransactionRef& tx) override
    {
        for (const auto& input : tx->vin) {
            if (const auto it{m_coins.find(input.prevout)}; it != m_coins.end()) it->second.Clear();
        }
    }
};

Snapshot ReadSnapshot(CWallet& wallet, const UniValue& request)
{
    auto& chain{wallet.chain()};
    const auto before{chain.getTipLocator().vHave};
    Snapshot result{chain.getHeight().value_or(0), {}, {}, {}};
    if (request.exists("coinbase")) {
        result.coinbase = Outpoint(request["coinbase"]);
        result.coins.emplace(result.coinbase, Coin{});
    }
    if (request.exists("payment")) {
        result.payment = Outpoint(request["payment"]);
        if (result.payment == result.coinbase) throw std::runtime_error("Coinbase and payment outpoints must differ");
        result.coins.emplace(result.payment, Coin{});
    }
    if (!result.coins.empty()) {
        chain.findCoins(result.coins);
        // findCoins includes mempool-created outputs but does not exclude mempool spends.
        MempoolSpends spends{result.coins};
        chain.requestMempoolTransactions(spends);
    }
    if (before != chain.getTipLocator().vHave) throw std::runtime_error("Chain changed; retry with a fresh snapshot");
    return result;
}

const Coin& CheckCoin(const Snapshot& snapshot, const Offer& offer, bool payment, int confirmations)
{
    const auto& coin{snapshot.coins.at(payment ? snapshot.payment : snapshot.coinbase)};
    if (coin.IsSpent()) throw std::runtime_error("UTXO spent or missing; historical state unknown");
    if (coin.IsCoinBase() != !payment || coin.out.nValue != (payment ? offer.payment_amount : offer.coinbase_amount) ||
        coin.out.scriptPubKey != OutputScript(offer, payment) ||
        (!payment && coin.nHeight != static_cast<unsigned int>(offer.coinbase_height))) throw std::runtime_error("UTXO does not match offer");
    if (confirmations > 0 && (coin.nHeight > static_cast<unsigned int>(snapshot.tip) ||
        int64_t{snapshot.tip} - coin.nHeight + 1 < confirmations)) throw std::runtime_error("UTXO needs at least six confirmations");
    return coin;
}

std::string EncodePSBT(const PartiallySignedTransaction& psbt)
{
    DataStream stream;
    stream << psbt;
    return EncodeBase64(stream.str());
}

CFeeRate ReserveRate(CWallet& wallet)
{
    const auto minimum{std::max(wallet.chain().relayMinFee(), wallet.chain().mempoolMinFee()).GetFeePerK()};
    // The spending API accepts integral sat/vB, so round its current floor up.
    return CFeeRate{std::max<int64_t>(1, (minimum + 999) / 1000) * 1000};
}

void CheckChainReady(CWallet& wallet)
{
    if (!wallet.chain().isReadyToBroadcast()) throw std::runtime_error("Chain not ready: loading blocks or initial block download");
}

void CheckOfferEconomics(CWallet& wallet, const Offer& offer, const CFeeRate& rate)
{
    CheckEconomicReserve(offer, rate);
    for (const bool payment : {false, true}) {
        const auto value{payment ? offer.payment_amount : offer.coinbase_amount};
        if (IsDust(CTxOut{value - value / 100, OutputScript(offer, payment)}, wallet.chain().relayDustFee())) {
            throw std::runtime_error("Dust HTLC or recovery reserve at current relay dust policy");
        }
    }
}

UniValue Describe(const Offer& offer)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("warning", WARNING);
    result.pushKV("offer", EncodeOffer(offer, Params().GenesisBlock().GetHash()));
    result.pushKV("coinbase_address", EncodeDestination(WitnessV0ScriptHash{Script(offer, false)}));
    result.pushKV("payment_address", EncodeDestination(WitnessV0ScriptHash{Script(offer, true)}));
    result.pushKV("coinbase_witness_script", HexStr(Script(offer, false)));
    result.pushKV("payment_witness_script", HexStr(Script(offer, true)));
    result.pushKV("conservative_maturity", ConservativeMaturity(Params().GetConsensus()));
    return result;
}

UniValue Spend(CWallet& wallet, const UniValue& request, bool payment)
{
    const auto signing_rules{SighashRulesForSigning()};
    // Respect scheduled-fork replay protection without returning a signature
    // that cannot enter the next block. Legacy signing requires explicit opt-out.
    if (signing_rules == SighashRules::UNIFIED &&
        int64_t{wallet.chain().getHeight().value_or(0)} + 1 < Params().GetConsensus().Blake2bHeight) {
        throw std::runtime_error("Unified signatures are not block-valid before scheduled Blake2b activation; wait or explicitly configure -walletoldsigs=1");
    }
    if (payment) {
        CheckFields(request, {"offer", "coinbase", "payment", "destination", "fee_rate", "mode"}, {"secret"});
    } else {
        CheckFields(request, {"offer", "coinbase", "destination", "fee_rate", "mode"}, {"secret"});
    }
    const auto offer{ParseOffer(request["offer"], Params().GenesisBlock().GetHash(), Params().GetConsensus())};
    const std::string mode{request["mode"].get_str()};
    const bool claim{mode == "claim"};
    if (!claim && mode != (payment ? "refund" : "recovery")) throw std::runtime_error("Unsupported spend mode");
    if (claim) CheckChainReady(wallet);
    if (!claim && request.exists("secret")) throw std::runtime_error("Secret is forbidden in refund/recovery mode");
    std::vector<unsigned char> secret;
    if (claim) {
        if (!request.exists("secret") || request["secret"].get_str().size() != 64 || !IsHex(request["secret"].get_str())) throw std::runtime_error("32-byte secret required");
        secret = ParseHex(request["secret"].get_str());
        if (!MatchesSecret(offer, secret)) throw std::runtime_error("Secret does not match offer");
    }
    const auto snapshot{ReadSnapshot(wallet, request)};
    // The miner must check BOTH legs before producing a signature that reveals the preimage.
    const Coin* coin{nullptr};
    if (claim || !payment) coin = &CheckCoin(snapshot, offer, false, MIN_CONFIRMATIONS);
    if (payment) {
        const auto& payment_coin{CheckCoin(snapshot, offer, true, MIN_CONFIRMATIONS)};
        if (payment) coin = &payment_coin;
    }
    const int timeout{payment ? offer.payment_timeout : offer.recovery_timeout};
    if (claim) {
        CheckClaimWindow(snapshot.tip, timeout);
        if (payment) CheckClaimWindow(snapshot.tip, offer.payment_timeout);
    } else if (snapshot.tip < timeout) {
        throw std::runtime_error("Refund/recovery timeout has not been reached");
    }
    if (!payment && !ConservativelyMature(snapshot.tip, offer.coinbase_height, Params().GetConsensus())) {
        throw std::runtime_error("Coinbase has not reached conservative maturity");
    }
    const auto destination{DecodeDestination(request["destination"].get_str())};
    if (!IsValidDestination(destination) || std::holds_alternative<WitnessUnknown>(destination) ||
        GetScriptForDestination(destination).size() > 34) throw std::runtime_error("Invalid or unsupported destination");
    // sat/vB, integral to avoid rounding surprises and cap the experimental fee budget.
    const int64_t rate{request["fee_rate"].getInt<int64_t>()};
    const auto minimum{std::max(wallet.chain().relayMinFee(), wallet.chain().mempoolMinFee())};
    if (rate < 1 || rate > 1000 || CFeeRate{rate * 1000} < minimum) throw std::runtime_error("Fee rate below relay/mempool minimum or above 1000 sat/vB");
    CMutableTransaction tx;
    tx.nLockTime = claim ? 0 : timeout;
    tx.vin.emplace_back(payment ? snapshot.payment : snapshot.coinbase, CScript{}, MAX_BIP125_RBF_SEQUENCE);
    tx.vout.emplace_back(coin->out.nValue, GetScriptForDestination(destination));
    const auto script{Script(offer, payment)};
    tx.vin[0].scriptWitness = Witness(script, std::vector<unsigned char>(73), secret, claim);
    const auto fee{CFeeRate{rate * 1000}.GetFee(GetVirtualTransactionSize(CTransaction{tx}))};
    if (fee > coin->out.nValue / 100 || coin->out.nValue - fee < MIN_OUTPUT_AMOUNT) throw std::runtime_error("Fee exceeds one percent budget or output is uneconomic");
    if (payment && claim) CheckOfferEconomics(wallet, offer, CFeeRate{rate * 1000});
    tx.vout[0].nValue -= fee;
    if (IsDust(tx.vout[0], wallet.chain().relayDustFee())) throw std::runtime_error("Dust destination");
    tx.vin[0].scriptWitness.SetNull();
    PartiallySignedTransaction psbt{tx};
    psbt.inputs[0].witness_utxo = coin->out;
    psbt.inputs[0].witness_script = script;
    psbt.inputs[0].sighash_type = SIGHASH_ALL | (signing_rules == SighashRules::UNIFIED ? SIGHASH_UNIFIED : 0);
    UniValue result{UniValue::VOBJ};
    result.pushKV("warning", WARNING);
    result.pushKV("fee", ValueFromAmount(fee));
    result.pushKV("psbt", EncodePSBT(psbt));
    result.pushKV("complete", false);
    const auto& key{payment ? (claim ? offer.miner : offer.buyer) : (claim ? offer.buyer : offer.miner)};
    LOCK(wallet.cs_wallet);
    EnsureWalletIsUnlocked(wallet);
    for (auto* manager : wallet.GetAllScriptPubKeyMans()) {
        auto* descriptor{dynamic_cast<DescriptorScriptPubKeyMan*>(manager)};
        auto provider{descriptor ? descriptor->GetSigningProvider(key) : manager->GetSolvingProvider(GetScriptForDestination(PKHash{key}))};
        if (!provider) continue;
        PrecomputedTransactionData txdata;
        txdata.Init(tx, {coin->out}, true);
        MutableTransactionSignatureCreator creator{tx, 0, coin->out.nValue, &txdata, SIGHASH_ALL};
        creator.SetSighashRules(signing_rules);
        std::vector<unsigned char> signature;
        if (!creator.CreateSig(*provider, signature, key.GetID(), script, SigVersion::WITNESS_V0)) continue;
        tx.vin[0].scriptWitness = Witness(script, signature, secret, claim);
        const uint32_t flags{STANDARD_SCRIPT_VERIFY_FLAGS | (SighashRulesForVerifying() == SighashRules::UNIFIED ? uint32_t{SCRIPT_VERIFY_UNIFIED_SIGHASH} : 0)};
        // Never return a "complete" raw transaction until its custom witness has been checked.
        if (!VerifyScript(tx.vin[0].scriptSig, coin->out.scriptPubKey, &tx.vin[0].scriptWitness, flags, creator.Checker())) throw std::runtime_error("HTLC signature verification failed");
        result.pushKV("complete", true);
        result.pushKV("hex", EncodeHexTx(CTransaction{tx}));
        break;
    }
    return result;
}

RPCHelpMan Command(const std::string& name, const std::string& description, std::function<UniValue(CWallet&, const UniValue&)> handler)
{
    return RPCHelpMan{name,
        std::string{WARNING} + "\n" + description + "\nStateless snapshot only. No transaction is broadcast. Generic wallet PSBT signing cannot finalize these HTLCs. Signing follows scheduled-fork replay protection; -walletoldsigs=1 explicitly opts out. Spend builders refuse unified signatures until next-block activation rules permit them.\n",
        {{"request", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Strict request object; see doc/coinbase-liquidity-prototype.md.", {}, RPCArgOptions{.skip_type_check = true}}},
        RPCResult{RPCResult::Type::OBJ, "", "Experimental result", {{RPCResult::Type::ELISION, "", "warning and operation-specific fields"}}},
        RPCExamples{HelpExampleCli(name, "'{\"offer\":{...}}'")},
        [handler](const RPCHelpMan&, const JSONRPCRequest& request) {
            auto& context{EnsureWalletContext(request.context)};
            if (!context.args->GetBoolArg("-enablecoinbaseliquidityproto", false)) throw JSONRPCError(RPC_MISC_ERROR, std::string{WARNING} + "; enable -enablecoinbaseliquidityproto=1");
            const auto wallet{GetWalletForJSONRPCRequest(request)};
            if (!wallet) return UniValue{};
            wallet->BlockUntilSyncedToCurrentChain();
            try {
                return handler(*wallet, request.params[0]);
            } catch (const UniValue& error) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string{WARNING} + ": " + error["message"].get_str());
            } catch (const std::exception& error) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string{WARNING} + ": " + error.what());
            }
        }};
}
} // namespace

RPCHelpMan createcoinbasefinancingoffer()
{
    return Command("createcoinbasefinancingoffer", "Before mining, commit to a 32-byte secret hash and two compressed public keys. Request fields: buyer_pubkey, miner_pubkey, secret_hash, coinbase_amount, payment_amount, coinbase_height, payment_timeout, recovery_timeout. No secret is generated or stored.", [](CWallet& wallet, const UniValue& request) {
        CheckFields(request, {"buyer_pubkey", "miner_pubkey", "secret_hash", "coinbase_amount", "payment_amount", "coinbase_height", "payment_timeout", "recovery_timeout"});
        UniValue object{request};
        object.pushKV("version", 1);
        object.pushKV("genesis", Params().GenesisBlock().GetHash().GetHex());
        const auto offer{ParseOffer(object, Params().GenesisBlock().GetHash(), Params().GetConsensus())};
        if (offer.coinbase_height <= wallet.chain().getHeight().value_or(0)) throw std::runtime_error("Offer must be created before mining");
        CheckOfferEconomics(wallet, offer, ReserveRate(wallet));
        return Describe(offer);
    });
}

RPCHelpMan decodecoinbasefinancingoffer()
{
    return Command("decodecoinbasefinancingoffer", "Validate and decode request {offer}, including current local fee and dust-policy economic reserves. Only version 1, network-bound native P2WSH offers are supported.", [](CWallet& wallet, const UniValue& request) {
        CheckFields(request, {"offer"});
        const auto offer{ParseOffer(request["offer"], Params().GenesisBlock().GetHash(), Params().GetConsensus())};
        CheckOfferEconomics(wallet, offer, ReserveRate(wallet));
        return Describe(offer);
    });
}

RPCHelpMan createbuyerfundinghtlc()
{
    return Command("createbuyerfundinghtlc", "Request {offer,coinbase:{txid,vout}}. Verify the canonical confirmed coinbase, then return an empty-input payment PSBT and outputs. Explicitly fund outputs with walletcreatefundedpsbt, review/sign and broadcast separately.", [](CWallet& wallet, const UniValue& request) {
        CheckFields(request, {"offer", "coinbase"});
        CheckChainReady(wallet);
        const auto offer{ParseOffer(request["offer"], Params().GenesisBlock().GetHash(), Params().GetConsensus())};
        const auto snapshot{ReadSnapshot(wallet, request)};
        CheckCoin(snapshot, offer, false, MIN_CONFIRMATIONS);
        CheckClaimWindow(snapshot.tip + MIN_CONFIRMATIONS, offer.payment_timeout);
        CheckOfferEconomics(wallet, offer, ReserveRate(wallet));
        CMutableTransaction tx;
        tx.vout.emplace_back(offer.payment_amount, OutputScript(offer, true));
        UniValue outputs{UniValue::VOBJ}, result{Describe(offer)};
        outputs.pushKV(EncodeDestination(WitnessV0ScriptHash{Script(offer, true)}), ValueFromAmount(offer.payment_amount));
        result.pushKV("outputs", outputs);
        PartiallySignedTransaction psbt{tx};
        psbt.outputs[0].witness_script = Script(offer, true);
        result.pushKV("psbt", EncodePSBT(psbt));
        return result;
    });
}

RPCHelpMan claimbuyerfundinghtlc()
{
    return Command("claimbuyerfundinghtlc", "Request {offer,coinbase,payment,destination,fee_rate,mode,secret?}. Outpoints are {txid,vout}; integral fee_rate is sat/vB. mode=claim reveals the miner's secret only after BOTH UTXOs have six confirmations and a safe window remains; mode=refund spends as buyer after payment_timeout without needing the coinbase UTXO. Returns metadata PSBT, complete, and locally verified signed hex if wallet owns the branch key.", [](CWallet& wallet, const UniValue& request) { return Spend(wallet, request, true); });
}

RPCHelpMan createbuyerredemptiontx()
{
    return Command("createbuyerredemptiontx", "Request {offer,coinbase,destination,fee_rate,mode,secret?}. mode=claim spends mature coinbase as buyer using secret (the miner may already have spent the payment); mode=recovery spends as miner after recovery_timeout without secret or payment. Returns metadata PSBT, complete and verified signed hex if branch key is available.", [](CWallet& wallet, const UniValue& request) { return Spend(wallet, request, false); });
}

RPCHelpMan getcoinbasefinancingstatus()
{
    return Command("getcoinbasefinancingstatus", "Request {offer,coinbase?,payment?}. Snapshot only: unknown means no outpoint supplied; spent_or_missing does not infer history. Unspent mismatches are errors. Includes confirmations and conservative maturity/window indicators, not a persisted contract state.", [](CWallet& wallet, const UniValue& request) {
        CheckFields(request, {"offer"}, {"coinbase", "payment"});
        const auto offer{ParseOffer(request["offer"], Params().GenesisBlock().GetHash(), Params().GetConsensus())};
        const auto snapshot{ReadSnapshot(wallet, request)};
        UniValue result{UniValue::VOBJ};
        result.pushKV("warning", WARNING);
        result.pushKV("snapshot_height", snapshot.tip);
        for (const bool payment : {false, true}) {
            const char* name{payment ? "payment" : "coinbase"};
            UniValue state{UniValue::VOBJ};
            state.pushKV("state", !request.exists(name) ? "unknown" : snapshot.coins.at(payment ? snapshot.payment : snapshot.coinbase).IsSpent() ? "spent_or_missing" : "unspent");
            if (request.exists(name) && !snapshot.coins.at(payment ? snapshot.payment : snapshot.coinbase).IsSpent()) {
                const auto& coin{CheckCoin(snapshot, offer, payment, 0)};
                state.pushKV("confirmations", std::max<int64_t>(0, int64_t{snapshot.tip} - coin.nHeight + 1));
            }
            result.pushKV(name, state);
        }
        result.pushKV("conservatively_mature", ConservativelyMature(snapshot.tip, offer.coinbase_height, Params().GetConsensus()));
        result.pushKV("payment_claim_window", HasClaimWindow(snapshot.tip, offer.payment_timeout));
        return result;
    });
}
} // namespace wallet
