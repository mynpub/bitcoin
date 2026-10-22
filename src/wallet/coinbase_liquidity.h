// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#ifndef BITCOIN_WALLET_COINBASE_LIQUIDITY_H
#define BITCOIN_WALLET_COINBASE_LIQUIDITY_H

#include <consensus/amount.h>
#include <pubkey.h>
#include <script/script.h>
#include <univalue.h>
#include <uint256.h>

#include <initializer_list>
#include <vector>

namespace Consensus { struct Params; }
class CFeeRate;
namespace wallet::liquidity {
inline constexpr const char* WARNING{"EXPERIMENTAL, NOT FOR PRODUCTION FUNDS"};
inline constexpr int MIN_CONFIRMATIONS{6};
inline constexpr int SAFETY_BLOCKS{12};
inline constexpr CAmount MIN_AMOUNT{20000};
inline constexpr CAmount MIN_OUTPUT_AMOUNT{1000};

struct Offer {
    CPubKey buyer;
    CPubKey miner;
    std::vector<unsigned char> hash;
    CAmount coinbase_amount;
    CAmount payment_amount;
    int coinbase_height;
    int payment_timeout;
    int recovery_timeout;
};

void CheckFields(const UniValue& object, std::initializer_list<const char*> required, std::initializer_list<const char*> optional = {});
int ConservativeMaturity(const Consensus::Params& params);
Offer ParseOffer(const UniValue& object, const uint256& genesis, const Consensus::Params& params);
UniValue EncodeOffer(const Offer& offer, const uint256& genesis);
CScript Script(const Offer& offer, bool payment);
CScript OutputScript(const Offer& offer, bool payment);
CScriptWitness Witness(const CScript& script, const std::vector<unsigned char>& signature, const std::vector<unsigned char>& secret, bool claim);
bool MatchesSecret(const Offer& offer, const std::vector<unsigned char>& secret);
bool ConservativelyMature(int tip, int coinbase_height, const Consensus::Params& params);
bool HasClaimWindow(int tip, int timeout);
void CheckClaimWindow(int tip, int timeout);
void CheckEconomicReserve(const Offer& offer, const CFeeRate& fee_rate);
} // namespace wallet::liquidity
#endif
