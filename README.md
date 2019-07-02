# Godot-PIVX

A GDNative lib to enable using PIVX in your game, via a LibBTC backend, bundled with an example project. After downloading this lib, you will need to set it up.


## Linux Install Guide:

```
cd Godot-PIVX

git clone https://github.com/GodotNativeTools/godot_headers
cd PIVX/src

git clone https://github.com/libbtc/libbtc
cd libbtc
./autogen
./configure CFLAGS='-fPIC' --disable-wallet --disable-tools --disable-net
make

cd ../
gcc --std=c11 -Wno-implicit-function-declaration -fPIC -o PIVX.o -I../../godot_headers -I./libbtc/include/btc --include "sys/types.h" -c PIVX.c
gcc -fPIC --shared -o ../bin/libPIVX.so PIVX.o libbtc/.libs/libbtc.a libbtc/src/secp256k1/.libs/libsecp256k1.a -lgmp
```

## Functions

- `newPrivateKey`: Creates a new Wallet inside the class instance. Always returns true.
- `getPrivateKey`: Returns the WIF for this Wallet.
- `loadPrivateKey`: Takes in a WIF string and loads it into this class instance. Returns true on success and false on failure.
- `getAddress`: Returns the address for this Wallet.
- `newTX`: Returns a hex serialized transaction to be broadcasted on the PIVX mainnet. The first argument is an array of arrays. Each child array has a string of the TX hash to spend, an int of the output we're spending, and a string of how much it's worth. The second argument is a string of the destination address. The third is a string of the amount to send. The fourth is a string of the fee to pay (not per k/b). All quantities are denoted in Satoshi.
