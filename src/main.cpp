#include "qPapelEasyAuth.h"
#include "VMProtectSDK.h"
#include <iostream>
#include <windows.h>

// Protected function example (remapped and wiped from original memory)
__declspec(noinline) static int CalculateSecurePayload(int a, int b) {
    VMProtectBeginUltra(_XOR_("EasyAuth_Secure_Calculation"));
    int result = ((a * b) ^ (a + b)) + 42;
    VMProtectEnd();
    return result;
}

int main() {
    // 1. Config
    qPapelEasyAuth::config cfg;
    cfg.flags = qPapelEasyAuth::flag_all;
    cfg.honeypot_delay_ms = 5000;
    cfg.vmp_mode = false;
    cfg.vmp_enforce_protected = false;
    qPapelEasyAuth::set_config(cfg);

    // 2. Register protected function
    void* orig_fn = reinterpret_cast<void*>(&CalculateSecurePayload);
    qPapelEasyAuth::register_protected_function(orig_fn);

    // 3. Initialize engine
    qPapelEasyAuth::initialize();

    // 5. Connect
    std::cout << "[*] Connecting to qPapelEasyAuth Server...\n";
    bool net_ok = qPapelEasyAuth::network_connect();
    if (!net_ok) {
        std::cout << "[-] Connection: OFFLINE\n";
        Sleep(3000);
        return 1;
    }

    std::string api_key = _XOR_("pk_00000073_1381695181994e4ea94eabf54911520b");
    auto init_res = qPapelEasyAuth::init_session(api_key);
    if (!init_res.success) {
        std::cout << "[-] Session Init Failed: " << init_res.message << "\n";
        Sleep(3000);
        return 1;
    }

    std::cout << "[+] Connection : CONNECTED\n";
    std::cout << "[+] Security   : " << (qPapelEasyAuth::is_debugger_detected() ? "FLAGGED" : "CLEAN") << "\n";
    std::cout << "[+] VM Machine : " << (qPapelEasyAuth::is_virtual_machine() ? "DETECTED (VM)" : "PHYSICAL PC") << "\n\n";

    // 6. Authenticate
    std::string license_key;
    std::cout << "Enter License Key: ";
    std::cin >> license_key;

    std::cout << "[*] Authenticating...\n";
    auto auth_res = qPapelEasyAuth::authenticate(license_key, api_key);

    if (auth_res.success) {
        std::cout << "\n[SUCCESS] Authentication Verified!\n";
        std::cout << "[*] Expire Date : " << (auth_res.expire_date.empty() ? "Lifetime" : auth_res.expire_date) << "\n\n";
        
        int test_val = CalculateSecurePayload(10, 20);
        std::cout << "[+] Protected Function Result: " << test_val << "\n";
    } else {
        std::cout << "\n[-] Auth Failed: " << auth_res.message << " (Code: " << auth_res.error_code << ")\n";
        Sleep(3000);
        return 1;
    }

    // Other features reference:

    // Server-side variables
    // std::string val = easyauth::get_variable("my_variable_access_id", license_key, api_key);
    // auto val_ex = easyauth::get_variable_ex("my_variable_access_id", license_key, api_key);

    // Server-side file download (chunked)
    // auto file = easyauth::get_file("file_access_id", license_key, api_key);
    // easyauth::download_file_to_disk("file_access_id", "C:\\output.dll", license_key, api_key);
    // easyauth::get_file("file_access_id", license_key, api_key, [](size_t dl, size_t total, float pct) {
    //     printf("\rDownload Progress: %.1f%%", pct);
    // });

    // Server-side manual map
    // auto map = easyauth::server_map("file_access_id", "target.exe", license_key, api_key);

    // Protection checks
    // bool tampered = easyauth::protection_check();
    // bool hooked = easyauth::is_hooked(fn_ptr);
    // bool injected = easyauth::is_injection_detected();
    // bool net_hooks = easyauth::scan_network_hooks();
    // bool dbg = easyauth::is_debugger_detected();

    // Honeypot
    // easyauth::arm_honeypot(5000);
    // bool armed = easyauth::is_honeypot_armed();

    // VMProtect
    // bool vmp = easyauth::is_vmp_protected();
    // bool vmp_crc = easyauth::is_vmp_valid_crc();
    // bool vmp_dbg = easyauth::is_vmp_debugger_present(true);

    // Network utilities
    // uint32_t latency;
    // easyauth::network_ping(latency);
    // bool alive = easyauth::network_is_connected();
    // easyauth::network_reconnect();
    // easyauth::network_disconnect();

    // Watchdog
    // easyauth::start_background_watchdog(500);
    // easyauth::stop_background_watchdog();
    // uint32_t checks = easyauth::get_background_check_count();

    // Screenshot & report
    // std::string token = easyauth::capture_screen();
    // easyauth::upload_screenshot("routine", api_key);
    // easyauth::report_suspicious("Cheat engine detected", "tamper", true, "critical", api_key);

    // Remote blacklist
    // easyauth::scan_and_enforce_remote_blacklists();

    // Remap & memory wiping
    // bool remapped = easyauth::is_remapped();
    // bool wiped = easyauth::is_wiped(orig_fn);
    // void* safe_fn = easyauth::get_remapped(orig_fn);

    // Protection flag toggle
    // easyauth::enable_protection_flag(easyauth::flag_antidebug);
    // easyauth::disable_protection_flag(easyauth::flag_crc32);
    // bool enabled = easyauth::is_protection_enabled(easyauth::flag_honeypot);

    // Thread hiding
    // easyauth::hide_thread();

    // Plugin system
    // easyauth::plugins::register_plugin(my_plugin);
    // easyauth::plugins::unregister_plugin("custom_game_detector");
    // easyauth::plugins::enable_plugin("custom_game_detector");
    // easyauth::plugins::disable_plugin("custom_game_detector");
    // auto infos = easyauth::plugins::get_all_plugin_info();
    // auto resp = easyauth::plugins::send_plugin_custom_request("action", "{}");

    std::cout << "\nPress Enter to exit...\n";
    std::cin.ignore();
    std::cin.get();
    return 0;
}
