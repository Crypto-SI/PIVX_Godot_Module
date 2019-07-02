#include <stdio.h>

#include <gmp.h>

#include <gdnative_api_struct.gen.h>

#include "btc.h"
#include "chainparams.h"
#include "ecc_key.h"

#include "Util.h"
#include "TX.h"

GodotAPI api = NULL;
GodotExtensionAPI nativescript_api = NULL;

void GDN_EXPORT godot_gdnative_init(
    godot_gdnative_init_options* options
) {
    api = options->api_struct;

    for (int i = 0; i < api->num_extensions; i++) {
        switch (api->extensions[i]->type) {
            case GDNATIVE_EXT_NATIVESCRIPT:
                nativescript_api = (GodotExtensionAPI) api->extensions[i];
                break;

            default:
                break;
        }
    }
}

void GDN_EXPORT godot_gdnative_terminate(
    godot_gdnative_terminate_options* options
) {
    api = NULL;
    nativescript_api = NULL;
}

typedef struct {
    btc_chainparams chainParams;
    btc_key* privKey;
    char* address;
} UserData;

void* pivx_constructor(
    godot_object* instance,
    void* method
) {
    UserData* data = api->godot_alloc(sizeof(UserData));

    btc_ecc_start();
    data->chainParams.b58prefix_pubkey_address = 30;
    data->chainParams.b58prefix_script_address = 13;
    data->chainParams.b58prefix_secret_address = 212;

    return data;
}

void pivx_destructor(
    godot_object* instance,
    void* method,
    void* userData
) {
    api->godot_free(userData);
}

godot_variant newPrivateKey(
    godot_object* instance,
    void* method,
    void* userDataArg,
    int argc,
    godot_variant** argv
) {
    UserData* userData = (UserData*) userDataArg;

    userData->privKey = api->godot_alloc(sizeof(btc_key));
    btc_privkey_init(userData->privKey);
    btc_privkey_gen(userData->privKey);

    btc_pubkey* pubKey = api->godot_alloc(sizeof(btc_pubkey));
    btc_pubkey_init(pubKey);
    btc_pubkey_from_key(userData->privKey, pubKey);

    userData->address = api->godot_alloc(36);
    btc_pubkey_getaddr_p2pkh(pubKey, &(userData->chainParams), userData->address);

    api->godot_free(pubKey);

    return boolToGodot(api, GODOT_TRUE);
}

godot_variant getPrivateKey(
    godot_object* instance,
    void* method,
    void* userDataArg,
    int argc,
    godot_variant** argv
) {
    UserData* userData = (UserData*) userDataArg;

    size_t len = 53;
    char* wif = api->godot_alloc(len);

    btc_privkey_encode_wif(userData->privKey, &(userData->chainParams), wif, &len);

    return cstringToGodot(api, wif);
}

godot_variant loadPrivateKey(
    godot_object* instance,
    void* method,
    void* userDataArg,
    int argc,
    godot_variant** argv
) {
    UserData* userData = (UserData*) userDataArg;

    char* wif = godotToCString(api, *argv[0]);

    btc_key* key = api->godot_alloc(sizeof(btc_key));
    if (btc_privkey_decode_wif(wif, &(userData->chainParams), key) != 1) {
        return boolToGodot(api, GODOT_FALSE);
    }
    userData->privKey = key;

    api->godot_free(wif);

    btc_pubkey* pubKey = api->godot_alloc(sizeof(btc_pubkey));
    btc_pubkey_init(pubKey);
    btc_pubkey_from_key(userData->privKey, pubKey);

    userData->address = api->godot_alloc(36);
    btc_pubkey_getaddr_p2pkh(pubKey, &(userData->chainParams), userData->address);

    api->godot_free(pubKey);

    return boolToGodot(api, GODOT_TRUE);
}

godot_variant getAddress(
    godot_object* instance,
    void* method,
    void* userDataArg,
    int argc,
    godot_variant** argv
) {
    UserData* userData = (UserData*) userDataArg;

    return cstringToGodot(api, userData->address);
}

godot_variant newTX(
    godot_object* instance,
    void* method,
    void* userDataArg,
    int argc,
    godot_variant** argv
) {
    UserData* userData = (UserData*) userDataArg;

    TX tx;
    godot_array inputsArr = api->godot_variant_as_array(argv[0]);
    tx.inputsLen = api->godot_array_size(&inputsArr);

    if (
        (tx.inputsLen < 1) ||
        (255 < tx.inputsLen)
    ) {
        return boolToGodot(api, GODOT_FALSE);
    }

    tx.inputs = api->godot_alloc(tx.inputsLen * sizeof(Input));
    for (int i = 0; i < tx.inputsLen; i++) {
        godot_variant inputVar = api->godot_array_get(&inputsArr, i);
        godot_array inputArr = api->godot_variant_as_array(&inputVar);

        tx.inputs[i].hash = hexToReserveBinary(api, godotToCString(api, api->godot_array_get(&inputArr, 0)));
        tx.inputs[i].output = godotToInt(api, api->godot_array_get(&inputArr, 1));

        if (
            (tx.inputs[i].output < 1) ||
            (255 < tx.inputs[i].output)
        ) {
            return boolToGodot(api, GODOT_FALSE);
        }

        tx.inputs[i].amount = newGMPFromDecimal(api, godotToCString(api, api->godot_array_get(&inputArr, 2)));
    }

    mpz_t* inputSum = newGMP(api);
    for (int i =  0; i < tx.inputsLen; i++) {
        mpz_add(*inputSum, *inputSum, *tx.inputs[i].amount);
    }

    char* address = godotToCString(api, *argv[1]);
    mpz_t* amount = newGMPFromDecimal(api, godotToCString(api, *argv[2]));
    mpz_t* fee = newGMPFromDecimal(api, godotToCString(api, *argv[3]));

    mpz_t* outputSum = newGMPFromGMP(api, amount);
    mpz_add(*outputSum, *outputSum, *fee);

    mpz_t* change = newGMPFromGMP(api, inputSum);
    mpz_sub(*change, *change, *outputSum);

    if (mpz_cmp_si(*change, 0) < 0) {
        return boolToGodot(api, GODOT_FALSE);
    } else if (mpz_cmp_si(*change, 0) == 0) {
        tx.outputs = api->godot_alloc(sizeof(Output));
        tx.outputsLen = 1;
    } else {
        tx.outputs = api->godot_alloc(2 * sizeof(Output));
        tx.outputsLen = 2;
        tx.outputs[1].amount = change;
        tx.outputs[1].address = userData->address;
    }

    tx.outputs[0].amount = amount;
    tx.outputs[0].address = address;

    sign(api, &tx, userData->privKey, userData->address);
    int length = serialize(api, &tx, userData->privKey, userData->address);

    api->godot_free(address);
    api->godot_free(amount);
    api->godot_free(fee);
    api->godot_free(outputSum);
    api->godot_free(change);

    size_t hexLength = (length * 2) + 1;
    char* serialized = api->godot_alloc(hexLength);
    utils_bin_to_hex(
        tx.serialized,
        length,
        serialized
    );

    for (int i = 0; i < tx.inputsLen; i++) {
        api->godot_free(tx.inputs[i].hash);
        api->godot_free(tx.inputs[i].amount);
        api->godot_free(tx.inputs[i].signing);
        api->godot_free(tx.inputs[i].signature);
    }
    api->godot_free(tx.inputs);

    api->godot_free(tx.serialized);

    return cstringToGodot(api, serialized);
}

void GDN_EXPORT godot_nativescript_init(
    void* handle
) {
    godot_instance_create_func create = {
        NULL,
        NULL,
        NULL
    };
    create.create_func = &pivx_constructor;

    godot_instance_destroy_func destroy = {
        NULL,
        NULL,
        NULL
    };
    destroy.destroy_func = &pivx_destructor;

    nativescript_api->godot_nativescript_register_class(
        handle,
        "PIVX",
        "Reference",
        create,
        destroy
    );

    godot_method_attributes attributes = {
        GODOT_METHOD_RPC_MODE_DISABLED
    };

    godot_instance_method godot_newPrivateKey = {
        NULL,
        NULL,
        NULL
    };
    godot_newPrivateKey.method = &newPrivateKey;
    nativescript_api->godot_nativescript_register_method(
        handle,
        "PIVX",
        "newPrivateKey",
        attributes,
        godot_newPrivateKey
    );

    godot_instance_method godot_getPrivateKey = {
        NULL,
        NULL,
        NULL
    };
    godot_getPrivateKey.method = &getPrivateKey;
    nativescript_api->godot_nativescript_register_method(
        handle,
        "PIVX",
        "getPrivateKey",
        attributes,
        godot_getPrivateKey
    );

    godot_instance_method godot_loadPrivateKey = {
        NULL,
        NULL,
        NULL
    };
    godot_loadPrivateKey.method = &loadPrivateKey;
    nativescript_api->godot_nativescript_register_method(
        handle,
        "PIVX",
        "loadPrivateKey",
        attributes,
        godot_loadPrivateKey
    );

    godot_instance_method godot_getAddress = {
        NULL,
        NULL,
        NULL
    };
    godot_getAddress.method = &getAddress;
    nativescript_api->godot_nativescript_register_method(
        handle,
        "PIVX",
        "getAddress",
        attributes,
        godot_getAddress
    );

    godot_instance_method godot_newTX = {
        NULL,
        NULL,
        NULL
    };
    godot_newTX.method = &newTX;
    nativescript_api->godot_nativescript_register_method(
        handle,
        "PIVX",
        "newTX",
        attributes,
        godot_newTX
    );
}
