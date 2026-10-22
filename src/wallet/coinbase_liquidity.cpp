// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <wallet/coinbase_liquidity.h>

#include <consensus/consensus.h>
#include <consensus/params.h>
#include <core_io.h>
#include <crypto/sha256.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <rpc/util.h>
#include <script/solver.h>
#include <util/rbf.h>
#include <util/strencodings.h>

#include <algorithm>
#include <set>
#include <stdexcept>
#include <string>

namespace wallet::liquidity {
void CheckFields(const UniValue& object, std::initializer_list<const char*> required, std::initializer_list<const char*> optional)
{
    if (!object.isObject()) throw std::runtime_error("Expected an object");
    std::set<std::string> allowed{required.begin(), required.end()}, seen;
    allowed.insert(optional.begin(), optional.end());
    for (const auto& name : object.getKeys()) {
        if (!allowed.count(name) || !seen.insert(name).second) throw std::runtime_error("Unknown or duplicate field: " + name);
    }
    for (const auto* name : required) {
        if (!seen.count(name) || object[name].isNull()) throw std::runtime_error(std::string{"Missing field: "} + name);
    }
}

int ConservativeMaturity(const Consensus::Params& params)
{
    // Mempool policy applies the configured long maturity to every coinbase,
    // including coins outside the consensus deployment's creation/spend windows.
    return std::max(COINBASE_MATURITY, params.CoinbaseMaturityLong);
}

Offer ParseOffer(const UniValue& object, const uint256& genesis, const Consensus::Params& params)
{
    CheckFields(object, {"version", "genesis", "buyer_pubkey", "miner_pubkey", "secret_hash", "coinbase_amount", "payment_amount", "coinbase_height", "payment_timeout", "recovery_timeout"});
    if (object["version"].getInt<int>() != 1 || object["genesis"].get_str() != genesis.GetHex()) throw std::runtime_error("Unsupported offer version or network");
    auto pubkey = [&](const char* name) {
        const auto& hex = object[name].get_str();
        if (!IsHex(hex) || hex.size() != 66) throw std::runtime_error("Expected compressed public key");
        CPubKey key{ParseHex(hex)};
        if (!key.IsFullyValid() || !key.IsCompressed()) throw std::runtime_error("Invalid public key");
        return key;
    };
    const auto& hash = object["secret_hash"].get_str();
    if (!IsHex(hash) || hash.size() != 64) throw std::runtime_error("Expected 32-byte SHA256 hash");
    Offer offer{pubkey("buyer_pubkey"), pubkey("miner_pubkey"), ParseHex(hash),
                AmountFromValue(object["coinbase_amount"]), AmountFromValue(object["payment_amount"]),
                object["coinbase_height"].getInt<int>(), object["payment_timeout"].getInt<int>(), object["recovery_timeout"].getInt<int>()};
    if (offer.buyer == offer.miner) throw std::runtime_error("Buyer and miner keys must differ");
    if (offer.coinbase_amount < MIN_AMOUNT || offer.payment_amount < MIN_AMOUNT ||
        !MoneyRange(offer.coinbase_amount) || !MoneyRange(offer.payment_amount) ||
        offer.payment_amount > offer.coinbase_amount) throw std::runtime_error("Uneconomic or invalid offer amounts");
    if (offer.coinbase_height < 1 || offer.coinbase_height >= int64_t{LOCKTIME_THRESHOLD} ||
        offer.payment_timeout >= int64_t{LOCKTIME_THRESHOLD} || offer.recovery_timeout >= int64_t{LOCKTIME_THRESHOLD} ||
        int64_t{offer.payment_timeout} < int64_t{offer.coinbase_height} + 2 * MIN_CONFIRMATIONS + SAFETY_BLOCKS ||
        int64_t{offer.recovery_timeout} < int64_t{offer.coinbase_height} + ConservativeMaturity(params) + SAFETY_BLOCKS ||
        int64_t{offer.recovery_timeout} < int64_t{offer.payment_timeout} + SAFETY_BLOCKS) throw std::runtime_error("Unsafe timeout or maturity window");
    return offer;
}

UniValue EncodeOffer(const Offer& offer, const uint256& genesis)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("version", 1);
    result.pushKV("genesis", genesis.GetHex());
    result.pushKV("buyer_pubkey", HexStr(offer.buyer));
    result.pushKV("miner_pubkey", HexStr(offer.miner));
    result.pushKV("secret_hash", HexStr(offer.hash));
    result.pushKV("coinbase_amount", ValueFromAmount(offer.coinbase_amount));
    result.pushKV("payment_amount", ValueFromAmount(offer.payment_amount));
    result.pushKV("coinbase_height", offer.coinbase_height);
    result.pushKV("payment_timeout", offer.payment_timeout);
    result.pushKV("recovery_timeout", offer.recovery_timeout);
    return result;
}

CScript Script(const Offer& offer, bool payment)
{
    const auto& claim = payment ? offer.miner : offer.buyer;
    const auto& refund = payment ? offer.buyer : offer.miner;
    return CScript{} << OP_IF << OP_SIZE << 32 << OP_EQUALVERIFY << OP_SHA256 << offer.hash << OP_EQUALVERIFY
                     << ToByteVector(claim) << OP_CHECKSIG << OP_ELSE
                     << (payment ? offer.payment_timeout : offer.recovery_timeout)
                     << OP_CHECKLOCKTIMEVERIFY << OP_DROP << ToByteVector(refund) << OP_CHECKSIG << OP_ENDIF;
}

CScript OutputScript(const Offer& offer, bool payment)
{
    return GetScriptForDestination(WitnessV0ScriptHash{Script(offer, payment)});
}

CScriptWitness Witness(const CScript& script, const std::vector<unsigned char>& signature, const std::vector<unsigned char>& secret, bool claim)
{
    CScriptWitness witness;
    witness.stack.push_back(signature);
    if (claim) witness.stack.push_back(secret);
    witness.stack.push_back(claim ? std::vector<unsigned char>{1} : std::vector<unsigned char>{});
    witness.stack.emplace_back(script.begin(), script.end());
    return witness;
}

bool MatchesSecret(const Offer& offer, const std::vector<unsigned char>& secret)
{
    std::vector<unsigned char> hash(CSHA256::OUTPUT_SIZE);
    CSHA256().Write(secret.data(), secret.size()).Finalize(hash.data());
    return secret.size() == 32 && hash == offer.hash;
}

bool ConservativelyMature(int tip, int coinbase_height, const Consensus::Params& params)
{
    return int64_t{tip} + 1 - coinbase_height >= ConservativeMaturity(params);
}

bool HasClaimWindow(int tip, int timeout)
{
    return int64_t{timeout} - tip >= SAFETY_BLOCKS;
}

void CheckClaimWindow(int tip, int timeout)
{
    if (!HasClaimWindow(tip, timeout)) throw std::runtime_error("Insufficient claim window before timeout");
}

void CheckEconomicReserve(const Offer& offer, const CFeeRate& fee_rate)
{
    if (fee_rate.GetFeePerK() < 1000 || fee_rate.GetFeePerK() > 1000000) throw std::runtime_error("Unsupported reserve fee rate");
    for (const bool payment : {false, true}) {
        const auto value{payment ? offer.payment_amount : offer.coinbase_amount};
        for (const bool claim : {false, true}) {
            CMutableTransaction tx;
            tx.vin.emplace_back(COutPoint{}, CScript{}, MAX_BIP125_RBF_SEQUENCE);
            // Reserve for a maximum-size standard address output and signature.
            tx.vout.emplace_back(value, CScript{} << OP_0 << std::vector<unsigned char>(32));
            tx.vin[0].scriptWitness = Witness(Script(offer, payment), std::vector<unsigned char>(73), std::vector<unsigned char>(32), claim);
            const CAmount fee{fee_rate.GetFee(GetVirtualTransactionSize(CTransaction{tx}))};
            if (fee > value / 100 || value - fee < MIN_OUTPUT_AMOUNT) throw std::runtime_error("Fee exceeds one percent budget or future recovery reserve is uneconomic");
        }
    }
}
} // namespace wallet::liquidity
