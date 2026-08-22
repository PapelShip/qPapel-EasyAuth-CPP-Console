# easyauth cpp example

c++ client sdk example for easyauth authentication on windows x64.

## structure

- `include/` - header files (`qPapelEasyAuth.h`, `VMProtectSDK.h`)
- `lib/` - library files (`qPapelEasyAuth.lib`, `VMProtectSDK64.lib`)
- `qPapelTools/` - packer and core dll (`qPapelPacker.exe`, `qPapelEasyAuth.dll`)
- `src/` - example source code (`main.cpp`)

## build

1. open `EasyAuth-Example.sln` in visual studio 2022.
2. set configuration to **Release | x64**.
3. build the solution (`Ctrl+Shift+B`).

post-build event automatically runs `qPapelPacker.exe` to encrypt and embed `qPapelEasyAuth.dll` into the output executable:
```
x64\Release\EasyAuth-Example_packed.exe
```

only distribute `EasyAuth-Example_packed.exe`.

## quick start

```cpp
#include "qPapelEasyAuth.h"
#include <iostream>

int main() {
    easyauth::config cfg;
    cfg.flags = easyauth::flag_all;
    easyauth::set_config(cfg);

    easyauth::initialize();

    if (!easyauth::network_connect()) {
        std::cout << "connection failed\n";
        return 1;
    }

    std::string api_key = _XOR_("your_api_key");
    auto init_res = easyauth::init_session(api_key);
    if (!init_res.success) {
        std::cout << "session error: " << init_res.message << "\n";
        return 1;
    }

    auto auth_res = easyauth::authenticate("user_license_key", api_key);
    if (auth_res.success) {
        std::cout << "auth success, expire: " << auth_res.expire_date << "\n";
    } else {
        std::cout << "auth failed: " << auth_res.message << "\n";
    }

    return 0;
}
```

## features

- **in-memory dll execution**: dll is decrypted in memory via aes-256-gcm and executed reflectively without writing to disk.
- **single header & lib**: everything included in `qPapelEasyAuth.h` and `qPapelEasyAuth.lib`.
- **string obfuscation**: compile-time string encryption via `_XOR_("string")`.
- **anti-debug & integrity**: peb checks, hardware breakpoint detection, thread hiding, memory crc32 and hook scanning.
- **remap**: sensitive functions are relocated in memory and wiped from original location.
- **server features**: dynamic variables, chunked file downloads up to 150mb, and server-side manual map.
- **plugins**: modern c++ plugin system via `easyauth::plugins::i_plugin`.
