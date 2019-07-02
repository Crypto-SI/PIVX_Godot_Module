#ifndef GODOT_PIVX_TX_H
#define GODOT_PIVX_TX_H

#include <stdlib.h>

#include <gmp.h>

#include "btc.h"
#include "hash.h"

#include "Util.h"

typedef struct {
    char* hash;
    int output;

    int signingLen;
    char* signing;

    size_t signatureLen;
    char* signature;

    mpz_t* amount;
} Input;

typedef struct {
    mpz_t* amount;
    char* address;
} Output;

typedef struct {
    int inputsLen;
    Input* inputs;

    int outputsLen;
    Output* outputs;

    char* serialized;
} TX;

void sign(
    GodotAPI api,
    TX* tx,
    btc_key* key,
    char* address
) {
    for (int i = 0; i < tx->inputsLen; i++) {
        int txLen = 34 + (tx->inputsLen * 66) + (tx->outputsLen * 34);
        tx->inputs[i].signing = api->godot_alloc(txLen);
        int offset = 4;

        for (int x = 0; x < txLen; x++) {
            tx->inputs[i].signing[x] = 0;
        }

        tx->inputs[i].signing[0] = 1;
        offset = 4;

        tx->inputs[i].signing[offset] = tx->inputsLen;
        offset++;

        char* addressHash;
        for (int x = 0; x < tx->inputsLen; x++) {
            memcpy(tx->inputs[i].signing + offset, tx->inputs[x].hash, 32);
            offset += 32;

            tx->inputs[i].signing[offset] = tx->inputs[x].output;
            offset += 4;

            if (i == x) {
                tx->inputs[i].signing[offset] = 25;
                tx->inputs[i].signing[offset + 1] = 0x76;
                tx->inputs[i].signing[offset + 2] = 0xa9;
                tx->inputs[i].signing[offset + 3] = 20;
                addressHash = addressToHash(api, address);
                memcpy(tx->inputs[i].signing + offset + 4, addressHash, 20);
                api->godot_free(addressHash);
                tx->inputs[i].signing[offset + 24] = 0x88;
                tx->inputs[i].signing[offset + 25] = 0xac;
                offset += 26;
            } else {
                offset++;
            }

            tx->inputs[i].signing[offset] = 255;
            tx->inputs[i].signing[offset + 1] = 255;
            tx->inputs[i].signing[offset + 2] = 255;
            tx->inputs[i].signing[offset + 3] = 255;
            offset += 4;
        }

        tx->inputs[i].signing[offset] = tx->outputsLen;
        offset++;

        for (int x = 0; x < tx->outputsLen; x++) {
            char* value = hexToReserveBinary(api, gmpToHex(api, tx->outputs[x].amount));
            memcpy(tx->inputs[i].signing + offset, value, strlen(value));
            api->godot_free(value);
            offset += 8;

            tx->inputs[i].signing[offset] = 25;
            tx->inputs[i].signing[offset + 1] = 0x76;
            tx->inputs[i].signing[offset + 2] = 0xa9;
            tx->inputs[i].signing[offset + 3] = 20;
            addressHash = addressToHash(api, tx->outputs[x].address);
            api->godot_free(addressHash);
            memcpy(tx->inputs[i].signing + offset + 4, addressHash, 20);
            tx->inputs[i].signing[offset + 24] = 0x88;
            tx->inputs[i].signing[offset + 25] = 0xac;
            offset += 26;
        }

        tx->inputs[i].signing[offset + 4] = 1;
        offset += 8;

        tx->inputs[i].signingLen = offset;

        uint8_t* hash = api->godot_alloc(32);
        tx->inputs[i].signatureLen = 80;
        tx->inputs[i].signature = api->godot_alloc(tx->inputs[i].signatureLen);

        btc_hash(tx->inputs[i].signing, offset, hash);
        btc_key_sign_hash(key, hash, tx->inputs[i].signature, &tx->inputs[i].signatureLen);

        api->godot_free(hash);
    }
}

int serialize(
    GodotAPI api,
    TX* tx,
    btc_key* key,
    char* address
) {
    int txLen = 34 + (tx->inputsLen * 150) + (tx->outputsLen * 34);
    tx->serialized = api->godot_alloc(txLen);
    char* addressHash = addressToHash(api, address);
    int offset = 4;

    for (int i = 0; i < txLen; i++) {
        tx->serialized[i] = 0;
    }

    tx->serialized[0] = 1;
    offset = 4;

    tx->serialized[offset] = tx->inputsLen;
    offset++;
    for (int i = 0; i < tx->inputsLen; i++) {
        memcpy(tx->serialized + offset, tx->inputs[i].hash, 32);
        offset += 32;

        tx->serialized[offset] = tx->inputs[i].output;
        offset += 4;

        tx->serialized[offset] = 36 + tx->inputs[i].signatureLen;
        tx->serialized[offset + 1] = tx->inputs[i].signatureLen + 1;
        memcpy(tx->serialized + offset + 2, tx->inputs[i].signature, tx->inputs[i].signatureLen);
        offset += 2 + tx->inputs[i].signatureLen;
        tx->serialized[offset] = 1;
        tx->serialized[offset + 1] = 33;
        offset += 2;

        btc_pubkey* pubKey = api->godot_alloc(sizeof(btc_pubkey));
        btc_pubkey_init(pubKey);
        btc_pubkey_from_key(key, pubKey);

        size_t hexLength = 66;
        char* hex = api->godot_alloc(hexLength);
        btc_pubkey_get_hex(pubKey, hex, &hexLength);

        int binLength = 33;
        char* bin = api->godot_alloc(33);
        utils_hex_to_bin(
            hex,
            bin,
            66,
            &binLength
        );
        memcpy(tx->serialized + offset, bin, 33);
        offset += 33;

        api->godot_free(pubKey);
        api->godot_free(hex);
        api->godot_free(bin);

        tx->serialized[offset] = 255;
        tx->serialized[offset + 1] = 255;
        tx->serialized[offset + 2] = 255;
        tx->serialized[offset + 3] = 255;
        offset += 4;
    }
    api->godot_free(addressHash);

    tx->serialized[offset] = tx->outputsLen;
    offset++;

    for (int i = 0; i < tx->outputsLen; i++) {
        char* value = hexToReserveBinary(api, gmpToHex(api, tx->outputs[i].amount));
        memcpy(tx->serialized + offset, value, strlen(value));
        api->godot_free(value);
        offset += 8;

        tx->serialized[offset] = 25;
        tx->serialized[offset + 1] = 0x76;
        tx->serialized[offset + 2] = 0xa9;
        tx->serialized[offset + 3] = 20;
        addressHash = addressToHash(api, tx->outputs[i].address);
        api->godot_free(addressHash);
        memcpy(tx->serialized + offset + 4, addressHash, 20);
        tx->serialized[offset + 24] = 0x88;
        tx->serialized[offset + 25] = 0xac;
        offset += 26;
    }

    offset += 4;
    return offset;
}

#endif
