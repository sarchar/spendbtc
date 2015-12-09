#!/bin/bash
import getpass
import json
import random
import os
import string
import subprocess
import sys
import traceback
import urllib
import urllib.request

import genaddress

unspent_source = "https://blockchain.info/unspent?active={}"
default_fee = '0.0001'

def format_bitcoins(satoshis):
    assert satoshis >= 0
    s = str(satoshis)
    if len(s) < 9:
        s = '0' * (9 - len(s)) + s
    right_of_decimal = s[-8:].rstrip('0')
    if len(right_of_decimal) == 0:
        right_of_decimal = '0'
    left_of_decimal = str(satoshis // 100000000)
    return "{}.{}".format(left_of_decimal, right_of_decimal)

#print(format_bitcoins(100000000))
#print(format_bitcoins(10000000))
#print(format_bitcoins(0))
#print(format_bitcoins(202000000))
#print(format_bitcoins(10000))
#print(format_bitcoins(1))

def parse_bitcoin_amount(s):
    s = s.lstrip().rstrip()
    assert s[0] != '-'
    assert len(set(s).difference(set(string.digits + "."))) == 0

    i = s.find('.')
    if i < 0: return int(s) * 100000000

    left, right = s.split('.')
    if len(left) == 0:
        left = '0'
    if len(right) == 0:
        return int(left) * 100000000
    assert len(right) <= 8
    d = len(right) - len(str(int(right)))
    a = (int(left) * 100000000) + (int(right) * 10**(8 - (len(str(int(right))) + d)))
    assert 0 <= a <= 21*1000000*100000000
    return a

#print(parse_bitcoin_amount("0"))
#print(parse_bitcoin_amount("1"))
#print(parse_bitcoin_amount("20"))
#print(parse_bitcoin_amount("0."))
#print(parse_bitcoin_amount("1."))
#print(parse_bitcoin_amount(".1"))
#print(parse_bitcoin_amount("1.1"))
#print(parse_bitcoin_amount("10.02"))
#print(parse_bitcoin_amount("0.00000001"))

def get_bitcoin_address(public_key, compressed):
    if compressed:
        compressed_public_key = genaddress.compress(public_key)
        addr = genaddress.base58_check(genaddress.hash160(compressed_public_key), version_bytes=genaddress.COINS['BTC']['main']['prefix'])
    else:
        addr = genaddress.address_from_data(public_key, version_bytes=genaddress.COINS['BTC']['main']['prefix'])
    return addr

def assert_bitcoin_address(src):
    decoded = genaddress.base58.decode(src)

    # version + hash160 + checksum
    decoded_bytes = decoded.to_bytes(25, 'big')

    version_byte = decoded_bytes[0]
    check = decoded_bytes[:-4]
    checksum = decoded_bytes[-4:]

    s = genaddress.hash256(check)
    if s[0:4] != checksum:
        raise Exception("invalid bitcoin address")

# assert_bitcoin_address("3Faj1Lk5dmEhjiVw2RRT5w8iRrAUiwY2z3")

def main():
    try:
        bitcoind = sys.argv[1]
        assert os.path.exists(bitcoind)
    except:
        print("usage: {} [path/to/bitcoind]".format(sys.argv[0]))
        sys.print_exc()

    print("\n\tInputs Time!!\n")

    private_keys = set()
    input_total = 0
    tx_inputs = []
    while True:
        print("Total private keys entered so far: {}".format(len(private_keys)))

        # Collect a private key (no private key = done). Disable terminal output
        pkstr = getpass.getpass("Provide a private key (ENTER for Done): ").strip()
        if len(pkstr) == 0: break

        # Display the bitcoin address of the private key
        try:
            _, compressed, privkey = genaddress.decode_base58_private_key(pkstr)
        except:
            print("*** Seems like an invalid private key. Are you sure you entered it correctly? ***")
            continue

        if pkstr in private_keys:
            print("*** You've already using that private key as an input. Try another. ***")
            continue

        pubkey = genaddress.get_public_key(privkey)
        address = get_bitcoin_address(pubkey, compressed)
        print("Address is {} (compressed = {}).".format(address, bool(compressed)))

        # Fetch unspent outputs as inputs. Display each input and total value of inputs
        print("Fetching unspent outputs...")
        url = unspent_source.format(address)
        try:
            response = urllib.request.urlopen(url)
            response_text = response.read().decode('utf8')
        except urllib.error.HTTPError as e:
            if e.code == 500:
                print("*** The server is responding with an error. Are you sure this address has unspent outputs? ***")
                continue
            else:
                raise
        except:
            print("*** Could not fetch unspent outputs. If you want to try again, re-enter the private key. ***")
            continue

        try:
            unspent = json.loads(response_text)
        except:
            print("*** Could not find any unspent outputs. Response given by server was: ***\n{}\n*** If you want to try again, re-enter the private key. ***".format(response_text.replace('\n','\n\t')))
            continue

        # Ask user to eliminate any inputs (no answer = done)
        unspent_outputs = list(unspent['unspent_outputs'])
        while len(unspent_outputs) > 0:
            address_total = 0
            for i, utxo in enumerate(unspent_outputs):
                print("    {}) {}:{} value={}".format(i, utxo['tx_hash_big_endian'], utxo['tx_output_n'], format_bitcoins(utxo['value'])))
                address_total += utxo['value']
            print("TOTAL = {}".format(format_bitcoins(address_total)))
            ri = input("Remove an input? (ENTER for Done): ").strip()

            if len(ri) == 0:
                break

            try:
                ri = int(ri)
                assert 0 <= ri < len(unspent_outputs)
            except:
                print("* Invalid. Try again. *")
                continue

            removed = unspent_outputs[ri]
            del unspent_outputs[ri]
            print("Removed input {} worth {}.".format(ri, format_bitcoins(removed['value'])))

        if len(unspent_outputs) == 0:
            print("No more inputs left for address {}. Skipping.".format(address))
            continue

        # Add the remaining address outputs to the tx inputs
        address_total = 0
        for utxo in unspent_outputs:
            address_total += utxo['value']
            input_total += utxo['value']
            tx_inputs.append({"txid": utxo["tx_hash_big_endian"], "vout": utxo["tx_output_n"], "scriptPubKey": utxo["script"]})

        # Display total value of all inputs
        private_keys.add(pkstr)
        print("Value added from {} is {}.".format(address, format_bitcoins(address_total)))
        print("Total value from all {} inputs is {}.".format(len(tx_inputs), format_bitcoins(input_total)))

    # No private keys? Done
    if len(tx_inputs) == 0 or len(private_keys) == 0:
        print("No private keys were provided. Quitting.")
        return

    # Shuffle inputs?
    if len(tx_inputs) >= 1:
        while True:
            yn = input("Would you like to shuffle the inputs to the transation? [Y/n] ").strip()
            if len(yn) == 0:
                yn = 'y'
            if len(yn) != 1 or yn not in 'YyNn':
                print("Invalid response. Try again.")
                continue
            if yn in 'Yn':
                random.shuffle(tx_inputs)
            break

    # Ask user what tx fee he wants to pay
    while True:
        feestr = input("What tx fee would you like to pay? [0.0001] ").strip()
        if len(feestr) == 0:
            feestr = default_fee
        try:
            fee = parse_bitcoin_amount(feestr)
            break
        except:
            print("Invalid response. Try again.")
            continue

    print("Fee set to {}.".format(format_bitcoins(fee)))

    # Deduct tx fee from remaining balance
    remaining_balance = input_total - fee

    print("\n\tOutputs Time!!\n")

    tx_outputs = []
    while True:
        # Display remaining balance
        print("There are Bitcoins left to be spent: {} BTC".format(format_bitcoins(remaining_balance)))

        # Ask for destination address (no address = done)
        dest = input("Send to what Bitcoin Address? ")
        assert_bitcoin_address(dest)

        # Ask for amount (in BTC, read as a string, parsed as a string)
        amount = input("Send how much (in BTC, decimal allowed)? ").strip()
        try:
            amount = parse_bitcoin_amount(amount)
            assert amount <= remaining_balance
        except:
            print("Invalid amount. Try again.")
            continue

        # Add the output and Subtract from balance
        print("Adding output of {} BTC to {}.".format(format_bitcoins(amount), dest))
        tx_outputs.append([dest, amount])
        remaining_balance -= amount

        # Done?
        print("Sending {} BTC to {} outputs.".format(format_bitcoins(input_total - fee - remaining_balance), len(tx_outputs)))
        if remaining_balance == 0:
            break

    assert len(tx_outputs) > 0

    # Shuffle outputs?
    while True:
        yn = input("Would you like to shuffle the outputs to the transation? [Y/n] ").strip()
        if len(yn) == 0:
            yn = 'y'
        if len(yn) != 1 or yn not in 'YyNn':
            print("Invalid response. Try again.")
            continue
        if yn in 'Yn':
            random.shuffle(tx_outputs)
        break

    print("createrawtransaction...", end='')
    sys.stdout.flush()
    unsigned = subprocess.check_output([bitcoind, "createrawtransaction", json.dumps(tx_inputs, separators=(',',':')), '{' + ','.join(["\"{}\":{}".format(address, format_bitcoins(amount)) for address, amount in tx_outputs]) + "}"])
    print("done")

    print("signrawtransaction...", end='')
    sys.stdout.flush()
    unsigned = unsigned.decode('ascii').strip()
    signed = subprocess.check_output([bitcoind, "signrawtransaction", unsigned, json.dumps(tx_inputs, separators=(',',':')), json.dumps([x for x in private_keys], separators=(',',':'))])
    print("done")

    try:
        tx = json.loads(signed.decode('ascii'))
        print("Your transaction is:\n{}".format(tx['hex']))
        print("\n\tBE SURE TO VERIFY THE TRANSACTION USING A DECODE TOOL!!!\n")
    except:
        print("Ooops. There was a problem generating your transaction.. Try again?")

if __name__ == "__main__":
    main()

