import os
import ecdsa
import hashlib
import bech32
import requests
import struct
import base64

"""
To do for btc:
1. generating btc wallet type bech32 (native segwit) ✅
2. checking balance of btc wallet ✅
3. sending btc from wallet to another address ✅
4. generating btc address from private key ✅
5. generate Multisig addres bech32 (native segwit) 
"""
import os
import ecdsa
import hashlib
import bech32

class btc:

    @staticmethod
    def generate_multisig_address(pubkey1_hex, pubkey2_hex):

        privkey1 = os.urandom(32)
        privkey1_hex = privkey1.hex()
        sk1 = ecdsa.SigningKey.from_string(privkey1, curve=ecdsa.SECP256k1)
        vk1 = sk1.verifying_key
        pubkey1 = b'\x02' + vk1.to_string()[:32] if vk1.to_string()[-1] % 2 == 0 else b'\x03' + vk1.to_string()[:32]
        pubkey1_hex = pubkey1.hex()

        pubkey2 = bytes.fromhex(pubkey2_hex)

        pubkeys = sorted([pubkey1, pubkey2])
        redeem_script = (
            b'\x52' +  # OP_2
            bytes([len(pubkeys[0])]) + pubkeys[0] +
            bytes([len(pubkeys[1])]) + pubkeys[1] +
            b'\x52' +  # OP_2
            b'\xae'    # OP_CHECKMULTISIG
        )
        # Hash redeem script for P2WSH
        sha256_redeem = hashlib.sha256(redeem_script).digest()

        bech32_addr = bech32.encode('bc', 0, sha256_redeem)
        return bech32_addr, privkey1_hex



    def generate_btc_bech32_address():
        privkey = os.urandom(32)
        privkey_hex = privkey.hex()

        sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        public_key = b'\x02' + vk.to_string()[:32] if vk.to_string()[-1] % 2 == 0 else b'\x03' + vk.to_string()[:32]

        sha256_pk = hashlib.sha256(public_key).digest()
        ripemd160_pk = hashlib.new('ripemd160', sha256_pk).digest()

        witness_version = 0
        witness_program = ripemd160_pk
        bech32_addr = bech32.encode('bc', witness_version, witness_program)

        return privkey_hex, bech32_addr

    def check_wallet_address(privkey_hex):
        privkey = bytes.fromhex(privkey_hex)
        sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        public_key = b'\x02' + vk.to_string()[:32] if vk.to_string()[-1] % 2 == 0 else b'\x03' + vk.to_string()[:32]

        sha256_pk = hashlib.sha256(public_key).digest()
        ripemd160_pk = hashlib.new('ripemd160', sha256_pk).digest()

        witness_version = 0
        witness_program = ripemd160_pk
        bech32_addr = bech32.encode('bc', witness_version, witness_program)

        return bech32_addr

    def check_balance(wallet):
        api_url = f"https://blockstream.info/api/address/{wallet}"

        response = requests.get(api_url)
        if response.status_code == 200:
            funded_txo_sum = response.json().get('chain_stats', {}).get('funded_txo_sum', 0)
            spent_txo_sum = response.json().get('chain_stats', {}).get('spent_txo_sum', 0)
            balance = funded_txo_sum - spent_txo_sum
            return balance / 1e8 
        else:
            return {"error": "Cos misjaczku poslo nie tak."}
    def send_btc(from_address, to_address, amount, privkey_hex, fee=800):  # fee in sats
        """
        Send BTC from one bech32 (P2WPKH) address to another.
        amount: in BTC
        fee: in satoshis (default 800 sats)
        """

        SATOSHI = 100_000_000
        amount_sats = int(amount * SATOSHI)

        utxo_url = f"https://blockstream.info/api/address/{from_address}/utxo"
        utxos = requests.get(utxo_url).json()
        if not utxos:
            return {"error": "No UTXOs found for this address."}

        selected_utxos = []
        total = 0
        for utxo in utxos:
            selected_utxos.append(utxo)
            total += utxo['value']
            if total >= amount_sats + fee:
                break
        if total < amount_sats + fee:
            return {"error": "Insufficient funds."}

        change = total - amount_sats - fee

        def varint(n):
            if n < 0xfd:
                return struct.pack('<B', n)
            elif n <= 0xffff:
                return b'\xfd' + struct.pack('<H', n)
            elif n <= 0xffffffff:
                return b'\xfe' + struct.pack('<I', n)
            else:
                return b'\xff' + struct.pack('<Q', n)

        def address_to_scriptpubkey(addr):
            hrp, witver, witprog = bech32.decode('bc', addr)
            if witver != 0:
                raise ValueError("Only segwit v0 supported")
            return bytes([0x00, 0x14]) + witprog

        txins = b''
        for utxo in selected_utxos:
            txins += bytes.fromhex(utxo['txid'])[::-1]
            txins += struct.pack('<I', utxo['vout'])
            txins += b'\x00'
            txins += b'\xff\xff\xff\xff'  

        txouts = b''
        to_script = address_to_scriptpubkey(to_address)
        txouts += struct.pack('<Q', amount_sats)
        txouts += bytes([len(to_script)]) + to_script
        if change > 0:
            change_script = address_to_scriptpubkey(from_address)
            txouts += struct.pack('<Q', change)
            txouts += bytes([len(change_script)]) + change_script

        version = struct.pack('<I', 2)
        marker = b'\x00'
        flag = b'\x01'
        txin_count = varint(len(selected_utxos))
        txout_count = varint(1 + (1 if change > 0 else 0))
        locktime = struct.pack('<I', 0)

        privkey = bytes.fromhex(privkey_hex)
        sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        public_key = b'\x02' + vk.to_string()[:32] if vk.to_string()[-1] % 2 == 0 else b'\x03' + vk.to_string()[:32]

        def hash160(x):
            return hashlib.new('ripemd160', hashlib.sha256(x).digest()).digest()

        def bip143_sighash(idx, utxo):
            prevouts = b''.join([
                bytes.fromhex(u['txid'])[::-1] + struct.pack('<I', u['vout'])
                for u in selected_utxos
            ])
            hashPrevouts = hashlib.sha256(hashlib.sha256(prevouts).digest()).digest()
            sequences = b''.join([b'\xff\xff\xff\xff' for _ in selected_utxos])
            hashSequence = hashlib.sha256(hashlib.sha256(sequences).digest()).digest()
            outs = txouts
            hashOutputs = hashlib.sha256(hashlib.sha256(outs).digest()).digest()
            outpoint = bytes.fromhex(utxo['txid'])[::-1] + struct.pack('<I', utxo['vout'])
            script_code = b'\x19\x76\xa9\x14' + hash160(public_key) + b'\x88\xac'
            value = struct.pack('<Q', utxo['value'])
            sequence = b'\xff\xff\xff\xff'
            sighash_type = struct.pack('<I', 1)
            preimage = (
                version +
                hashPrevouts +
                hashSequence +
                outpoint +
                script_code +
                value +
                sequence +
                hashOutputs +
                locktime +
                sighash_type
            )
            sighash = hashlib.sha256(hashlib.sha256(preimage).digest()).digest()
            return sighash

        witnesses = []
        for idx, utxo in enumerate(selected_utxos):
            sighash = bip143_sighash(idx, utxo)
            signature = sk.sign_digest(sighash, sigencode=ecdsa.util.sigencode_der_canonize) + b'\x01'
            witnesses.append([signature, public_key])

        tx = (
            version +
            marker +
            flag +
            txin_count +
            txins +
            txout_count +
            txouts
        )
        for w in witnesses:
            tx += varint(len(w))
            for item in w:
                tx += varint(len(item)) + item
        tx += locktime

        rawtx = tx.hex()

        push_url = "https://blockstream.info/api/tx"
        r = requests.post(push_url, data=rawtx)
        if r.status_code == 200:
            return {"txid": r.text.strip()}
        else:
            return {"error": f"Broadcast failed: {r.text}"}
