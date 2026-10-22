// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <wallet/coinbase_liquidity.h>

#include <chainparams.h>
#include <consensus/params.h>
#include <crypto/sha256.h>
#include <key.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <util/rbf.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
using namespace liquidity;
BOOST_FIXTURE_TEST_SUITE(coinbase_liquidity_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(offer_roundtrip_and_validation)
{
    CKey buyer, miner;
    buyer.MakeNewKey(true);
    miner.MakeNewKey(true);
    Consensus::Params params{};
    params.CoinbaseMaturityLong = 200;
    const Offer offer{buyer.GetPubKey(), miner.GetPubKey(), std::vector<unsigned char>(32, 7), COIN, COIN / 2, 100, 140, 312};
    const uint256 genesis{uint256::ONE};
    const auto encoded{EncodeOffer(offer, genesis)};
    BOOST_CHECK_EQUAL(EncodeOffer(ParseOffer(encoded, genesis, params), genesis).write(), encoded.write());
    BOOST_CHECK_EQUAL(ConservativeMaturity(params), 200);
    BOOST_CHECK_THROW(ParseOffer(encoded, uint256{}, params), std::runtime_error);
    for (const char* field : {"version", "buyer_pubkey", "miner_pubkey", "secret_hash", "coinbase_amount", "payment_amount", "coinbase_height", "payment_timeout", "recovery_timeout"}) {
        auto bad{encoded};
        bad.pushKV(field, 0);
        BOOST_CHECK_THROW(ParseOffer(bad, genesis, params), std::exception);
    }
    auto bad{encoded};
    bad.pushKV("secret", "must never be in an offer");
    BOOST_CHECK_THROW(ParseOffer(bad, genesis, params), std::runtime_error);
    bad = encoded;
    bad.pushKVEnd("version", 1);
    BOOST_CHECK_THROW(ParseOffer(bad, genesis, params), std::runtime_error);
    bad = encoded;
    bad.pushKV("buyer_pubkey", encoded["miner_pubkey"]);
    BOOST_CHECK_THROW(ParseOffer(bad, genesis, params), std::runtime_error);
    bad = encoded;
    bad.pushKV("recovery_timeout", 311);
    BOOST_CHECK_THROW(ParseOffer(bad, genesis, params), std::runtime_error);
    for (const char* height : {"coinbase_height", "payment_timeout", "recovery_timeout"}) {
        bad = encoded;
        bad.pushKV(height, 500000000);
        BOOST_CHECK_THROW(ParseOffer(bad, genesis, params), std::runtime_error);
    }
    BOOST_CHECK_NO_THROW(CheckClaimWindow(128, 140));
    BOOST_CHECK_THROW(CheckClaimWindow(129, 140), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(conservative_policy_maturity_on_production_networks)
{
    CKey buyer, miner;
    buyer.MakeNewKey(true);
    miner.MakeNewKey(true);
    for (const auto network : {ChainType::MAIN, ChainType::TESTNET4}) {
        const auto chain{CreateChainParams(*m_node.args, network)};
        const auto& params{chain->GetConsensus()};
        const auto genesis{chain->GenesisBlock().GetHash()};
        const int maturity{ConservativeMaturity(params)};
        BOOST_CHECK_EQUAL(maturity, network == ChainType::MAIN ? 6480 : 6705);
        // Relay policy does not narrow the long requirement to the consensus
        // deployment window, nor exempt coins mined before its start height.
        for (const int height : {1, params.CoinbaseMaturityLongStartHeight - 1,
                                 params.CoinbaseMaturityLongStartHeight,
                                 params.CoinbaseMaturityLongEnforceHeight,
                                 params.CoinbaseMaturityLongReleaseHeight + 1}) {
            Offer offer{buyer.GetPubKey(), miner.GetPubKey(), std::vector<unsigned char>(32, 7),
                        COIN, COIN / 2, height, height + 24, height + 100 + SAFETY_BLOCKS};
            BOOST_CHECK_THROW(ParseOffer(EncodeOffer(offer, genesis), genesis, params), std::runtime_error);
            offer.recovery_timeout = height + maturity + SAFETY_BLOCKS;
            BOOST_CHECK_NO_THROW(ParseOffer(EncodeOffer(offer, genesis), genesis, params));
            --offer.recovery_timeout;
            BOOST_CHECK_THROW(ParseOffer(EncodeOffer(offer, genesis), genesis, params), std::runtime_error);
        }
    }
    Consensus::Params short_policy{};
    short_policy.CoinbaseMaturityLong = 1;
    BOOST_CHECK_EQUAL(ConservativeMaturity(short_policy), 100);
}

BOOST_AUTO_TEST_CASE(canonical_witness_branches)
{
    CKey buyer, miner;
    buyer.MakeNewKey(true);
    miner.MakeNewKey(true);
    const std::vector<unsigned char> secret(32, 9);
    std::vector<unsigned char> hash(32);
    CSHA256().Write(secret.data(), secret.size()).Finalize(hash.data());
    const Offer offer{buyer.GetPubKey(), miner.GetPubKey(), hash, COIN, COIN / 2, 100, 150, 250};
    BOOST_CHECK(MatchesSecret(offer, secret));
    BOOST_CHECK(!MatchesSecret(offer, std::vector<unsigned char>(31, 9)));
    BOOST_CHECK(OutputScript(offer, true).IsPayToWitnessScriptHash());
    BOOST_CHECK(OutputScript(offer, true) != OutputScript(offer, false));
    for (bool payment : {false, true}) {
        for (bool claim : {false, true}) {
            const auto script{Script(offer, payment)};
            const auto& key{payment ? (claim ? miner : buyer) : (claim ? buyer : miner)};
            FlatSigningProvider provider;
            provider.keys.emplace(key.GetPubKey().GetID(), key);
            CMutableTransaction tx;
            tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0}, CScript{}, MAX_BIP125_RBF_SEQUENCE);
            tx.nLockTime = claim ? 0 : payment ? offer.payment_timeout : offer.recovery_timeout;
            tx.vout.emplace_back(COIN / 3, CScript{} << OP_TRUE);
            MutableTransactionSignatureCreator creator{tx, 0, COIN, SIGHASH_ALL};
            std::vector<unsigned char> signature;
            BOOST_REQUIRE(creator.CreateSig(provider, signature, key.GetPubKey().GetID(), script, SigVersion::WITNESS_V0));
            tx.vin[0].scriptWitness = Witness(script, signature, secret, claim);
            BOOST_CHECK_EQUAL(tx.vin[0].scriptWitness.stack.size(), claim ? 4 : 3);
            const auto output{OutputScript(offer, payment)};
            BOOST_CHECK(VerifyScript({}, output, &tx.vin[0].scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, creator.Checker()));
            BOOST_CHECK(SignalsOptInRBF(CTransaction{tx}));
            BOOST_CHECK(!VerifyScript({}, OutputScript(offer, !payment), &tx.vin[0].scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, creator.Checker()));
            auto bad_signature{tx.vin[0].scriptWitness};
            bad_signature.stack[0][0] ^= 1;
            BOOST_CHECK(!VerifyScript({}, output, &bad_signature, STANDARD_SCRIPT_VERIFY_FLAGS, creator.Checker()));
            if (claim) {
                auto wrong_secret{tx.vin[0].scriptWitness};
                wrong_secret.stack[1][0] ^= 1;
                BOOST_CHECK(!VerifyScript({}, output, &wrong_secret, STANDARD_SCRIPT_VERIFY_FLAGS, creator.Checker()));
                tx.vin[0].scriptWitness.stack[1].pop_back();
            } else {
                // CLTV must fail even with an otherwise valid signature.
                tx.nLockTime--;
            }
            BOOST_CHECK(!VerifyScript({}, output, &tx.vin[0].scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, creator.Checker()));
        }
    }
}

BOOST_AUTO_TEST_CASE(economic_reserve_for_each_leg)
{
    CKey buyer, miner;
    buyer.MakeNewKey(true);
    miner.MakeNewKey(true);
    Offer offer{buyer.GetPubKey(), miner.GetPubKey(), std::vector<unsigned char>(32, 7), COIN, COIN / 2, 100, 150, 250};
    BOOST_CHECK_NO_THROW(CheckEconomicReserve(offer, CFeeRate{1000}));
    BOOST_CHECK_NO_THROW(CheckEconomicReserve(offer, CFeeRate{1000000}));
    BOOST_CHECK_THROW(CheckEconomicReserve(offer, CFeeRate{999}), std::runtime_error);
    BOOST_CHECK_THROW(CheckEconomicReserve(offer, CFeeRate{1000001}), std::runtime_error);
    for (const bool payment : {false, true}) {
        auto uneconomic{offer};
        (payment ? uneconomic.payment_amount : uneconomic.coinbase_amount) = MIN_AMOUNT;
        BOOST_CHECK_NO_THROW(CheckEconomicReserve(uneconomic, CFeeRate{1000}));
        BOOST_CHECK_THROW(CheckEconomicReserve(uneconomic, CFeeRate{5000}), std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(snapshot_predicates_and_strict_fields)
{
    Consensus::Params params{};
    params.CoinbaseMaturityLong = 150;
    for (const auto& [tip, expected] : std::vector<std::pair<int, bool>>{{248, false}, {249, true}, {248, false}, {250, true}}) {
        BOOST_CHECK_EQUAL(ConservativelyMature(tip, 100, params), expected);
    }
    for (const auto& [tip, expected] : std::vector<std::pair<int, bool>>{{288, true}, {289, false}, {288, true}, {300, false}}) {
        BOOST_CHECK_EQUAL(HasClaimWindow(tip, 300), expected);
    }
    UniValue request{UniValue::VOBJ};
    request.pushKV("offer", UniValue{UniValue::VOBJ});
    BOOST_CHECK_THROW(CheckFields(request, {"offer", "coinbase"}), std::runtime_error);
    request.pushKV("coinbase", UniValue{UniValue::VOBJ});
    BOOST_CHECK_NO_THROW(CheckFields(request, {"offer", "coinbase"}, {"secret"}));
    auto invalid{request};
    invalid.pushKV("payment", UniValue{UniValue::VOBJ});
    BOOST_CHECK_THROW(CheckFields(invalid, {"offer", "coinbase"}, {"secret"}), std::runtime_error);
    invalid = request;
    invalid.pushKVEnd("offer", UniValue{UniValue::VOBJ});
    BOOST_CHECK_THROW(CheckFields(invalid, {"offer", "coinbase"}), std::runtime_error);
    invalid = request;
    invalid.pushKV("coinbase", UniValue{});
    BOOST_CHECK_THROW(CheckFields(invalid, {"offer", "coinbase"}), std::runtime_error);
    BOOST_CHECK_THROW(CheckFields(UniValue{UniValue::VARR}, {"offer"}), std::runtime_error);
}
BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
