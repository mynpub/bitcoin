#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/licenses/mit-license.php.
"""Opt-in, stateless coinbase financing: custom witnesses, reorgs and timeouts."""
from copy import deepcopy
from decimal import Decimal
from hashlib import sha256

from test_framework.script import SIGHASH_ALL, SIGHASH_UNIFIED
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


WARNING = "EXPERIMENTAL, NOT FOR PRODUCTION FUNDS"


class CoinbaseLiquidityTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=False)
        parser.add_argument("--unified", action="store_true", help="Exercise active Blake2b with unified wallet funding")
        parser.add_argument("--legacy-signatures", action="store_true", help="Sign legacy sighashes with Blake2b active")

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.wallet_names = []
        self.extra_args = [["-fallbackfee=0.00002000", "-minrelaytxfee=0.00001000",
                            "-testcoinbasematuritylong=1:105:151"]]
        if self.options.unified:
            self.extra_args[0].append("-testactivationheight=blake2b@1")
        if self.options.legacy_signatures:
            self.extra_args[0].append("-walletoldsigs=1")

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine(self, count):
        return self.generatetoaddress(self.nodes[0], count, self.mining_address)

    def error(self, message, method, request):
        assert_raises_rpc_error(-8, message, method, request)

    def contract(self):
        node = self.nodes[0]
        height = node.getblockcount() + 1
        request = {
            "buyer_pubkey": self.buyer.getaddressinfo(self.buyer.getnewaddress("", "bech32"))["pubkey"],
            "miner_pubkey": self.miner.getaddressinfo(self.miner.getnewaddress("", "bech32"))["pubkey"],
            "secret_hash": sha256(self.secret).hexdigest(),
            "coinbase_amount": Decimal(50) / (2 ** (height // 150)),
            "payment_amount": Decimal("0.1"),
            "coinbase_height": height,
            "payment_timeout": height + 45,
            "recovery_timeout": height + 162,
        }
        created = self.miner.createcoinbasefinancingoffer(request)
        assert_equal(created["warning"], WARNING)
        assert_equal(created["conservative_maturity"], 150)
        offer = created["offer"]
        assert_equal(self.buyer.decodecoinbasefinancingoffer({"offer": offer}), created)
        assert_equal(node.cli("-rpcwallet=buyer").decodecoinbasefinancingoffer({"offer": offer}), created)
        blockhash = self.generatetoaddress(node, 1, created["coinbase_address"])[0]
        coinbase = {"txid": node.getblock(blockhash)["tx"][0], "vout": 0}
        return created, coinbase, blockhash

    def fund(self, created, coinbase):
        prepared = self.buyer.createbuyerfundinghtlc({"offer": created["offer"], "coinbase": coinbase})
        assert_equal(prepared["warning"], WARNING)
        assert "witness_script" in self.nodes[0].decodepsbt(prepared["psbt"])["outputs"][0]
        funded = self.buyer.walletcreatefundedpsbt([], prepared["outputs"], 0, {"fee_rate": self.fee_rate})
        signed = self.buyer.walletprocesspsbt(funded["psbt"])
        final = self.nodes[0].finalizepsbt(signed["psbt"])
        assert_equal(final["complete"], True)
        txid = self.nodes[0].sendrawtransaction(final["hex"])
        outputs = self.nodes[0].decoderawtransaction(final["hex"])["vout"]
        vout = next(o["n"] for o in outputs if o["scriptPubKey"].get("address") == created["payment_address"])
        return {"txid": txid, "vout": vout}

    def spend_request(self, created, coinbase, payment=None, mode="claim"):
        request = {"offer": created["offer"], "coinbase": coinbase, "mode": mode,
                   "destination": self.mining_address, "fee_rate": self.fee_rate}
        if payment is not None:
            request["payment"] = payment
        if mode == "claim":
            request["secret"] = self.secret.hex()
        return request

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("buyer", load_on_startup=True)
        node.createwallet("miner", load_on_startup=True)
        self.buyer = node.get_wallet_rpc("buyer")
        self.miner = node.get_wallet_rpc("miner")
        for name in ("createcoinbasefinancingoffer", "decodecoinbasefinancingoffer", "createbuyerfundinghtlc",
                     "claimbuyerfundinghtlc", "createbuyerredemptiontx", "getcoinbasefinancingstatus"):
            assert_raises_rpc_error(-1, WARNING, getattr(self.miner, name), {})
        self.restart_node(0, self.extra_args[0] + ["-enablecoinbaseliquidityproto=1"])
        self.buyer = node.get_wallet_rpc("buyer")
        self.miner = node.get_wallet_rpc("miner")
        self.mining_address = self.buyer.getnewaddress("", "bech32")
        self.fee_rate = 2
        self.secret = bytes(range(32))
        assert_equal(node.getblockchaininfo()["initialblockdownload"], True)
        self.error("Chain not ready", self.buyer.createbuyerfundinghtlc, {"offer": {}, "coinbase": {}})
        self.mine(200)

        self.log.info("Offer validation, canonical coinbase binding and reveal ordering")
        created, coinbase, blockhash = self.contract()
        offer = created["offer"]
        self.error("six confirmations", self.buyer.createbuyerfundinghtlc, {"offer": offer, "coinbase": coinbase})
        for field, value in (("genesis", "00" * 32), ("version", 2), ("secret_hash", "00"),
                             ("buyer_pubkey", offer["miner_pubkey"]), ("payment_amount", "0.00000001"),
                             ("payment_timeout", offer["coinbase_height"] + 1),
                             ("recovery_timeout", offer["coinbase_height"] + 150)):
            bad = dict(offer, **{field: value})
            self.error(WARNING, self.buyer.decodecoinbasefinancingoffer, {"offer": bad})
        self.error("Unknown or duplicate", self.buyer.decodecoinbasefinancingoffer, {"offer": dict(offer, secret="00")})
        self.error(WARNING, self.buyer.decodecoinbasefinancingoffer, {"offer": dict(offer, payment_amount=-1)})
        self.mine(5)
        node.invalidateblock(blockhash)
        self.error("spent or missing", self.buyer.createbuyerfundinghtlc, {"offer": offer, "coinbase": coinbase})
        node.reconsiderblock(blockhash)
        mismatch = deepcopy(offer)
        mismatch["coinbase_amount"] -= Decimal("0.01")
        self.error("does not match", self.buyer.createbuyerfundinghtlc, {"offer": mismatch, "coinbase": coinbase})
        status = self.buyer.getcoinbasefinancingstatus({"offer": offer, "coinbase": coinbase})
        assert_equal(status["coinbase"]["confirmations"], 6)
        assert_equal(status["payment"]["state"], "unknown")
        self.restart_node(0, self.extra_args[0] + ["-enablecoinbaseliquidityproto=1", "-dustrelayfee=0.01000000"])
        self.buyer = node.get_wallet_rpc("buyer")
        self.miner = node.get_wallet_rpc("miner")
        dusty_offer = dict(offer, payment_amount=Decimal("0.0002"))
        self.error("Dust HTLC", self.buyer.decodecoinbasefinancingoffer, {"offer": dusty_offer})
        self.error("Dust HTLC", self.buyer.decodecoinbasefinancingoffer,
                   {"offer": dict(dusty_offer, coinbase_amount=Decimal("0.0002"))})
        self.error("Dust HTLC", self.buyer.createbuyerfundinghtlc, {"offer": dusty_offer, "coinbase": coinbase})
        dusty_request = {k: v for k, v in dusty_offer.items() if k not in ("genesis", "version")}
        height = node.getblockcount() + 1
        dusty_request.update(coinbase_height=height, payment_timeout=height + 45, recovery_timeout=height + 162)
        self.error("Dust HTLC", self.miner.createcoinbasefinancingoffer, dusty_request)
        self.error("Dust HTLC", self.miner.createcoinbasefinancingoffer,
                   dict(dusty_request, coinbase_amount=Decimal("0.0002")))
        self.restart_node(0, self.extra_args[0] + ["-enablecoinbaseliquidityproto=1"])
        self.buyer = node.get_wallet_rpc("buyer")
        self.miner = node.get_wallet_rpc("miner")
        payment = self.fund(created, coinbase)
        request = self.spend_request(created, coinbase, payment)
        self.error("six confirmations", self.miner.claimbuyerfundinghtlc, request)
        payment_blocks = self.mine(5)
        self.error("six confirmations", self.miner.claimbuyerfundinghtlc, request)
        payment_blocks += self.mine(1)
        node.invalidateblock(payment_blocks[0])
        self.error("six confirmations", self.miner.claimbuyerfundinghtlc, request)
        node.reconsiderblock(payment_blocks[0])
        # A once-adequate fee is not adequate after local policy rises.
        low_fee_claim = self.miner.claimbuyerfundinghtlc(request)
        assert_equal(node.testmempoolaccept([low_fee_claim["hex"]])[0]["allowed"], True)
        self.restart_node(0, self.extra_args[0] + ["-enablecoinbaseliquidityproto=1", "-minrelaytxfee=0.00005000"])
        self.buyer = node.get_wallet_rpc("buyer")
        self.miner = node.get_wallet_rpc("miner")
        stuck = node.testmempoolaccept([low_fee_claim["hex"]])[0]
        assert_equal(stuck["allowed"], False)
        assert "fee" in stuck["reject-reason"]
        self.error("Fee rate", self.miner.claimbuyerfundinghtlc, request)
        self.fee_rate = 5
        request["fee_rate"] = self.fee_rate
        uneconomic_offer = dict(offer, payment_amount=Decimal("0.0002"))
        self.error("future recovery reserve", self.buyer.decodecoinbasefinancingoffer, {"offer": uneconomic_offer})
        self.error("future recovery reserve", self.buyer.createbuyerfundinghtlc,
                   {"offer": uneconomic_offer, "coinbase": coinbase})
        next_height = node.getblockcount() + 1
        uneconomic_request = {k: v for k, v in uneconomic_offer.items() if k not in ("genesis", "version")}
        uneconomic_request.update(coinbase_height=next_height, payment_timeout=next_height + 45,
                                   recovery_timeout=next_height + 162)
        self.error("future recovery reserve", self.miner.createcoinbasefinancingoffer, uneconomic_request)
        self.error("Fee rate", self.miner.claimbuyerfundinghtlc, dict(request, fee_rate=0))
        self.error("Fee rate", self.miner.claimbuyerfundinghtlc, dict(request, fee_rate=1001))
        self.error("one percent budget", self.miner.claimbuyerfundinghtlc, dict(request, fee_rate=1000))
        self.error("Secret does not match", self.miner.claimbuyerfundinghtlc, dict(request, secret="11" * 32))
        for secret in ("00" * 31, "00" * 33, "ab" * 4096):
            self.error("32-byte secret required", self.miner.claimbuyerfundinghtlc, dict(request, secret=secret))
        self.error("Unknown or duplicate field: payment", self.buyer.createbuyerredemptiontx, request)
        self.error("must differ", self.miner.claimbuyerfundinghtlc,
                   dict(request, coinbase=payment))
        unavailable = self.buyer.claimbuyerfundinghtlc(request)
        assert_equal(unavailable["complete"], False)
        assert "hex" not in unavailable
        claim = self.miner.claimbuyerfundinghtlc(request)
        assert_equal(claim["complete"], True)
        psbt = node.decodepsbt(claim["psbt"])
        assert "witness_utxo" in psbt["inputs"][0]
        assert "witness_script" in psbt["inputs"][0]
        assert_equal(psbt["inputs"][0]["sighash"],
                     "ALL|UNIFIED" if self.options.unified and not self.options.legacy_signatures else "ALL")
        decoded = node.decoderawtransaction(claim["hex"])
        low_fee_decoded = node.decoderawtransaction(low_fee_claim["hex"])
        assert_equal(decoded["vin"][0]["txid"], low_fee_decoded["vin"][0]["txid"])
        assert_equal(decoded["vin"][0]["vout"], low_fee_decoded["vin"][0]["vout"])
        assert_equal(decoded["vout"][0]["scriptPubKey"], low_fee_decoded["vout"][0]["scriptPubKey"])
        assert claim["fee"] > low_fee_claim["fee"]
        assert_equal(decoded["vin"][0]["txinwitness"][1], self.secret.hex())
        assert_equal(bytes.fromhex(decoded["vin"][0]["txinwitness"][0])[-1],
                     SIGHASH_ALL | (SIGHASH_UNIFIED if self.options.unified and not self.options.legacy_signatures else 0))
        assert_equal(decoded["vin"][0]["sequence"], 0xfffffffd)
        assert_equal(decoded["vout"][0]["scriptPubKey"]["address"], self.mining_address)
        assert_equal(decoded["vout"][0]["value"] + claim["fee"], offer["payment_amount"])
        assert_equal(node.testmempoolaccept([claim["hex"]])[0]["allowed"], True)
        node.sendrawtransaction(claim["hex"])
        self.error("spent or missing", self.miner.claimbuyerfundinghtlc, request)
        assert_equal(self.buyer.getcoinbasefinancingstatus({"offer": offer, "payment": payment})["payment"]["state"], "spent_or_missing")
        claim_block = self.mine(1)[0]
        assert_equal(self.buyer.getcoinbasefinancingstatus({"offer": offer, "payment": payment})["payment"]["state"], "spent_or_missing")
        self.log.info("A reorg after disclosure cannot erase the known secret or imply historical completion")
        known_secret = bytes.fromhex(decoded["vin"][0]["txinwitness"][1])
        node.invalidateblock(claim_block)
        self.restart_node(0, self.extra_args[0] + ["-enablecoinbaseliquidityproto=1", "-minrelaytxfee=0.00005000",
                                                 "-persistmempool=0", "-walletbroadcast=0"])
        self.buyer = node.get_wallet_rpc("buyer")
        self.miner = node.get_wallet_rpc("miner")
        snapshot = self.buyer.getcoinbasefinancingstatus({"offer": offer, "coinbase": coinbase, "payment": payment})
        assert_equal(snapshot["payment"]["state"], "unspent")
        assert_equal(snapshot["coinbase"]["state"], "unspent")
        assert "completed" not in snapshot and "complete" not in snapshot
        assert_equal(known_secret, self.secret)
        assert_equal(node.testmempoolaccept([claim["hex"]])[0]["allowed"], True)
        node.reconsiderblock(claim_block)
        redeem = self.spend_request(created, coinbase)
        self.error("conservative maturity", self.buyer.createbuyerredemptiontx, redeem)
        # Height H+148 is still one block short for spending a conservatively 150-block coinbase.
        self.mine(offer["coinbase_height"] + 148 - node.getblockcount())
        self.error("conservative maturity", self.buyer.createbuyerredemptiontx, redeem)
        maturity_block = self.mine(1)[0]
        redemption = self.buyer.createbuyerredemptiontx(redeem)
        assert_equal(redemption["complete"], True)
        assert_equal(node.decoderawtransaction(redemption["hex"])["vin"][0]["sequence"], 0xfffffffd)
        assert_equal(node.testmempoolaccept([redemption["hex"]])[0]["allowed"], True)
        redemption_txid = node.sendrawtransaction(redemption["hex"])
        self.error("spent or missing", self.buyer.createbuyerredemptiontx, redeem)
        node.invalidateblock(maturity_block)
        assert redemption_txid not in node.getrawmempool()
        self.error("conservative maturity", self.buyer.createbuyerredemptiontx, redeem)
        premature = node.testmempoolaccept([redemption["hex"]])[0]
        assert_equal(premature["allowed"], False)
        assert "premature" in premature["reject-reason"]
        node.reconsiderblock(maturity_block)
        assert_equal(node.testmempoolaccept([redemption["hex"]])[0]["allowed"], True)
        assert_equal(self.buyer.createbuyerredemptiontx(redeem)["complete"], True)
        node.sendrawtransaction(redemption["hex"])
        self.mine(1)
        assert_equal(self.buyer.getcoinbasefinancingstatus({"offer": offer, "coinbase": coinbase})["coinbase"]["state"], "spent_or_missing")

        self.log.info("Buyer refund, no late reveal, and miner timeout recovery")
        created, coinbase, _ = self.contract()
        offer = created["offer"]
        self.mine(5)
        payment = self.fund(created, coinbase)
        self.mine(6)
        refund = self.spend_request(created, coinbase, payment, mode="refund")
        self.error("has not been reached", self.buyer.claimbuyerfundinghtlc, refund)
        self.mine(offer["payment_timeout"] - 11 - node.getblockcount())
        self.error("Insufficient claim window", self.miner.claimbuyerfundinghtlc,
                   self.spend_request(created, coinbase, payment))
        self.mine(11)
        signed = self.buyer.claimbuyerfundinghtlc(refund)
        assert_equal(signed["complete"], True)
        assert_equal(node.decoderawtransaction(signed["hex"])["vin"][0]["sequence"], 0xfffffffd)
        assert_equal(node.testmempoolaccept([signed["hex"]])[0]["allowed"], True)
        node.sendrawtransaction(signed["hex"])
        self.mine(1)
        recovery = self.spend_request(created, coinbase, mode="recovery")
        self.error("has not been reached", self.miner.createbuyerredemptiontx, recovery)
        self.mine(offer["recovery_timeout"] - 1 - node.getblockcount())
        self.error("has not been reached", self.miner.createbuyerredemptiontx, recovery)
        self.mine(1)
        signed = self.miner.createbuyerredemptiontx(recovery)
        assert_equal(signed["complete"], True)
        assert_equal(node.decoderawtransaction(signed["hex"])["vin"][0]["sequence"], 0xfffffffd)
        assert_equal(node.testmempoolaccept([signed["hex"]])[0]["allowed"], True)
        node.sendrawtransaction(signed["hex"])
        self.mine(1)
        if not self.options.unified:
            self.log.info("Scheduled-fork replay protection and explicit legacy signing opt-out")
            created, coinbase, _ = self.contract()
            self.mine(5)
            payment = self.fund(created, coinbase)
            self.mine(6)
            future = node.getblockcount() + 100
            self.restart_node(0, self.extra_args[0] + ["-enablecoinbaseliquidityproto=1",
                                                      f"-testactivationheight=blake2b@{future}"])
            self.buyer = node.get_wallet_rpc("buyer")
            self.miner = node.get_wallet_rpc("miner")
            request = self.spend_request(created, coinbase, payment)
            self.error("before scheduled Blake2b activation", self.miner.claimbuyerfundinghtlc, request)
            self.restart_node(0, self.extra_args[0] + ["-enablecoinbaseliquidityproto=1",
                                                      f"-testactivationheight=blake2b@{future}", "-walletoldsigs=1"])
            self.buyer = node.get_wallet_rpc("buyer")
            self.miner = node.get_wallet_rpc("miner")
            signed = self.miner.claimbuyerfundinghtlc(request)
            decoded = node.decoderawtransaction(signed["hex"])
            assert_equal(bytes.fromhex(decoded["vin"][0]["txinwitness"][0])[-1], SIGHASH_ALL)
            assert_equal(node.testmempoolaccept([signed["hex"]])[0]["allowed"], True)
            node.sendrawtransaction(signed["hex"])
            self.mine(1)
            self.mine(created["offer"]["coinbase_height"] + 149 - node.getblockcount())
            assert node.getblockcount() >= future
            self.restart_node(0, self.extra_args[0] + ["-enablecoinbaseliquidityproto=1",
                                                      f"-testactivationheight=blake2b@{future}"])
            self.buyer = node.get_wallet_rpc("buyer")
            signed = self.buyer.createbuyerredemptiontx(self.spend_request(created, coinbase))
            decoded = node.decoderawtransaction(signed["hex"])
            assert_equal(bytes.fromhex(decoded["vin"][0]["txinwitness"][0])[-1], SIGHASH_ALL | SIGHASH_UNIFIED)
            assert_equal(node.testmempoolaccept([signed["hex"]])[0]["allowed"], True)
            node.sendrawtransaction(signed["hex"])
            self.mine(1)


if __name__ == "__main__":
    CoinbaseLiquidityTest(__file__).main()
