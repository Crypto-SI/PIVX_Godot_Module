#ifndef GODOT_PIVX_UTIL_H
#define GODOT_PIVX_UTIL_H

#include <gmp.h>

#include <gdnative_api_struct.gen.h>

#include "btc.h"
#include "ecc_key.h"

typedef const godot_gdnative_core_api_struct* GodotAPI;
typedef const godot_gdnative_ext_nativescript_api_struct* GodotExtensionAPI;

char* hexToReserveBinary(
    GodotAPI api,
    char* hex
) {
    int binLen = strlen(hex) / 2;
    char* middle = api->godot_alloc(binLen + 1);
    char* result = api->godot_alloc(binLen + 1);
    int outLength;

    utils_hex_to_bin(
        hex,
        middle,
        strlen(hex),
        &outLength
    );
    for (int i = 0; i < binLen; i++) {
        result[i] = middle[binLen - i - 1];
    }

    api->godot_free(middle);

    return result;
}

char* addressToHash(
    GodotAPI api,
    char* address
) {
    char* middle = api->godot_alloc(36);
    char* bin = api->godot_alloc(20);

    btc_base58_decode_check(address, middle, 36);
    memcpy(bin, middle + 1, 20);

    api->godot_free(middle);

    return bin;
}

mpz_t* newGMP(
    GodotAPI api
) {
    mpz_t* num = api->godot_alloc(sizeof(mpz_t));
    mpz_init(*num);
    mpz_set_si(*num, 0);
    return num;
}

mpz_t* newGMPFromGMP(
    GodotAPI api,
    mpz_t* value
) {
    mpz_t* num = api->godot_alloc(sizeof(mpz_t));
    mpz_init_set(&(*num)[0], *value);
    return num;
}

mpz_t* newGMPFromDecimal(
    GodotAPI api,
    char* value
) {
    mpz_t* num = api->godot_alloc(sizeof(mpz_t));
    mpz_init_set_str(&(*num)[0], value, 10);
    return num;
}

mpz_t* newGMPFromHex(
    GodotAPI api,
    char* value
) {
    mpz_t* num = api->godot_alloc(sizeof(mpz_t));
    mpz_init_set_str(&(*num)[0], value, 16);
    return num;
}

char* gmpToCString(
    mpz_t* num
) {
    return mpz_get_str(NULL, 10, *num);
}

char* gmpToHex(
    GodotAPI api,
    mpz_t* num
) {
    char* middle = mpz_get_str(NULL, 16, *num);

    char* hex;
    int length;
    for (length = 0; middle[length] != '\0'; length++);
    
    if (length % 2 == 1) {
        hex = api->godot_alloc(length + 2);
        hex[0] = '0';
        memcpy(hex + 1, middle, length);

        return hex;
    }
    return middle;
}

godot_variant cstringToGodot(
    GodotAPI api,
    char* cstring
) {
    godot_string data;
    godot_variant result;

    api->godot_string_new(&data);
    api->godot_string_parse_utf8(&data, cstring);
    api->godot_variant_new_string(&result, &data);
    api->godot_string_destroy(&data);

    return result;
}

godot_variant boolToGodot(
    GodotAPI api,
    const godot_bool data
) {
    godot_variant result;
    api->godot_variant_new_bool(&result, data);
    return result;
}

char* godotToCString(
    GodotAPI api,
    godot_variant variant
) {
    godot_string str = api->godot_variant_as_string(&variant);
    godot_char_string charStr = api->godot_string_ascii(&str);
    return (char*) api->godot_char_string_get_data(&charStr);
}

int godotToInt(
    GodotAPI api,
    godot_variant variant
) {
    return api->godot_variant_as_int(&variant);
}

#endif
