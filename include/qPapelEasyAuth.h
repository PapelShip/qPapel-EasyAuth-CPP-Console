#pragma once

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <cstdint>
#include <cstddef>
#include <windows.h>

#pragma comment(lib, "qPapelEasyAuth.lib")
#pragma comment(lib, "bcrypt.lib")

#ifndef EASYAUTH_OBFUSCATE_DEFINED
#define EASYAUTH_OBFUSCATE_DEFINED

namespace easyauth {
    namespace obf {

        inline constexpr uint32_t seed_from_time() {
            uint32_t val = 0;
            val += (__TIME__[0] - '0') * 36000;
            val += (__TIME__[1] - '0') * 3600;
            val += (__TIME__[3] - '0') * 600;
            val += (__TIME__[4] - '0') * 60;
            val += (__TIME__[6] - '0') * 10;
            val += (__TIME__[7] - '0') * 1;
            return val;
        }

        inline constexpr uint32_t linear_congruential(uint32_t seed) {
            return 1664525u * seed + 1013904223u;
        }

        template <size_t N, uint32_t Key>
        class obfuscated_string {
        public:
            constexpr obfuscated_string(const char(&str)[N]) {
                uint32_t current_key = Key;
                for (size_t i = 0; i < N; ++i) {
                    encrypted_data_[i] = str[i] ^ static_cast<char>(current_key & 0xFF);
                    current_key = linear_congruential(current_key);
                }
            }

            const char* decrypt() const {
                if (!decrypted_) {
                    uint32_t current_key = Key;
                    for (size_t i = 0; i < N; ++i) {
                        decrypted_data_[i] = encrypted_data_[i] ^ static_cast<char>(current_key & 0xFF);
                        current_key = linear_congruential(current_key);
                    }
                    decrypted_data_[N - 1] = '\0';
                    decrypted_ = true;
                }
                return decrypted_data_;
            }

            std::string str() const {
                return std::string(decrypt());
            }

            operator const char* () const {
                return decrypt();
            }

        private:
            char encrypted_data_[N] = {};
            mutable char decrypted_data_[N] = {};
            mutable bool decrypted_ = false;
        };

        template <size_t N, uint32_t Key>
        class obfuscated_wstring {
        public:
            constexpr obfuscated_wstring(const wchar_t(&str)[N]) {
                uint32_t current_key = Key;
                for (size_t i = 0; i < N; ++i) {
                    encrypted_data_[i] = str[i] ^ static_cast<wchar_t>(current_key & 0xFFFF);
                    current_key = linear_congruential(current_key);
                }
            }

            const wchar_t* decrypt() const {
                if (!decrypted_) {
                    uint32_t current_key = Key;
                    for (size_t i = 0; i < N; ++i) {
                        decrypted_data_[i] = encrypted_data_[i] ^ static_cast<wchar_t>(current_key & 0xFFFF);
                        current_key = linear_congruential(current_key);
                    }
                    decrypted_data_[N - 1] = L'\0';
                    decrypted_ = true;
                }
                return decrypted_data_;
            }

            std::wstring str() const {
                return std::wstring(decrypt());
            }

            operator const wchar_t* () const {
                return decrypt();
            }

        private:
            wchar_t encrypted_data_[N] = {};
            mutable wchar_t decrypted_data_[N] = {};
            mutable bool decrypted_ = false;
        };

    } // namespace obf
} // namespace easyauth

#ifndef _XOR_
#define _XOR_(str) (::easyauth::obf::obfuscated_string<sizeof(str), ::easyauth::obf::seed_from_time() ^ (__COUNTER__ + 1)>(str).decrypt())
#endif
#ifndef _XORW_
#define _XORW_(str) (::easyauth::obf::obfuscated_wstring<sizeof(str) / sizeof(wchar_t), ::easyauth::obf::seed_from_time() ^ (__COUNTER__ + 1)>(str).decrypt())
#endif

#endif // EASYAUTH_OBFUSCATE_DEFINED

// C flat API
typedef void* QPCTX;

#define QP_SEC_FLAG_NONE                 0x00000000
#define QP_SEC_FLAG_ANTIDEBUG            0x00000001
#define QP_SEC_FLAG_TEXT_CRC32           0x00000002
#define QP_SEC_FLAG_REMAP_FUNCTIONS      0x00000004
#define QP_SEC_FLAG_HONEYPOT             0x00000008
#define QP_SEC_FLAG_LDASM_HOOK_SCAN      0x00000010
#define QP_SEC_FLAG_INJECTION_MONITOR    0x00000020
#define QP_SEC_FLAG_ALL                  0x0000003F

struct QP_ProductInfo {
    char product_id[64];
    char name[128];
    char version[32];
    char description[256];
    char access_level[32];
};

struct QP_PluginBridgeDescriptor {
    char id[64];
    char name[64];
    char version[32];
    char author[64];
    char signature_hash[65];
    uint32_t type_flags;
    bool is_critical;

    void* user_data;
    bool (*on_initialize)(void* user_data, void* ctx_handle);
    void (*on_shutdown)(void* user_data);
    void (*on_event)(void* user_data, int event_type, const char* event_json);
    bool (*on_security_check)(void* user_data, bool deep_scan, char* out_threat_name, char* out_category, char* out_data, int* out_severity);
    void (*append_telemetry)(void* user_data, void* collector_handle, void (*add_kv)(void* collector, const char* key, const char* val));
};

struct QP_PluginContextCallbacks {
    bool (*is_connected)(void* ctx_handle);
    bool (*get_ping)(void* ctx_handle, uint32_t* out_ms);
    char* (*send_custom_request)(void* ctx_handle, const char* action, const char* payload_json);
    bool (*report_threat)(void* ctx_handle, const char* reason, const char* threat_type, bool screenshot);
    void (*log_incident)(void* ctx_handle, int incident_type, const char* details);
    void (*trigger_honeypot)(void* ctx_handle, uint32_t delay_ms);
    void (*free_string)(char* str);
};

extern "C" {
    bool   QP_StubInit();
    QPCTX  QP_CreateContext();
    void   QP_DestroyContext(QPCTX ctx);
    void   QP_SetConfig(QPCTX ctx, const char* api_key, const char* version, int watchdog_ms, const char* hwid_method);
    void   QP_SetCustomHwid(QPCTX ctx, const char* custom_hwid);
    void   QP_SetCustomHwidCallback(QPCTX ctx, const char* (*cb)());
    void   QP_DisableWatchdog(QPCTX ctx);
    int    QP_SetDevEndpoint(QPCTX ctx, const char* host, unsigned short port, const char* dev_code);
    int    QP_Connect(QPCTX ctx);
    char* QP_InitSession(QPCTX ctx, const char* api_key);
    char* QP_Authenticate(QPCTX ctx, const char* key, const char* api_key);
    char* QP_GetLicenseInfo(QPCTX ctx, const char* key);
    char* QP_RegisterComputer(QPCTX ctx, const char* api_key);
    char* QP_FetchString(QPCTX ctx, const char* access_id, const char* key, const char* api_key);
    int    QP_FetchFile(QPCTX ctx, const char* access_id, const char* key, const char* api_key, unsigned char** out_data, int* out_size);
    int    QP_DownloadFileToDisk(QPCTX ctx, const char* access_id, const char* out_path, const char* key, const char* api_key);
    int    QP_RunFile(QPCTX ctx, const char* access_id, const char* key, const char* api_key);
    int    QP_ServerMapper(QPCTX ctx, const char* access_id, const char* target_process, const char* key, const char* api_key);
    int    QP_CheckIntegrity(QPCTX ctx);
    int    QP_CheckDebugger(QPCTX ctx);
    void   QP_ReportEvent(QPCTX ctx, const char* reason, const char* type, const char* severity);
    void   QP_OptimizeClock(QPCTX ctx);
    char* QP_GetLastStatus(QPCTX ctx);
    char* QP_GetToken(QPCTX ctx);
    char* QP_DecryptLogBuffer();
    char* QP_EnumChannels(QPCTX ctx, const char* key);
    char* QP_RequestBlock(QPCTX ctx, const char* block_id, const char* key, const char* api_key);
    int    QP_ReadSegment(QPCTX ctx, const char* seg_id, int offset, const char* key, unsigned char** out_data, int* out_size);
    void   QP_FreeString(char* str);
    void   QP_FreeBytes(unsigned char* bytes);
    int    QP_PE_LoadProduct(QPCTX ctx, const char* product_id, const char* key, char** out_data, unsigned int* out_size);
    int    QP_GetAvailableProducts(QPCTX ctx, const char* key, QP_ProductInfo* out_products, int max_products, int* out_count);
    char* QP_GetAutoLoginKey(QPCTX ctx);
    void   QP_GetTraceUuid(QPCTX ctx, char* out_uuid, int max_len);
    int    QP_GetTraceHierarchy(QPCTX ctx, int* out_hierarchy, int max_count);
    char* QP_RunSecurityChecks(QPCTX ctx);
    void   QP_SetSecurityFlags(QPCTX ctx, unsigned int flags);
    unsigned int QP_GetSecurityFlags(QPCTX ctx);
    int    QP_AntiDebug_CheckAll();
    int    QP_AntiDebug_HideThread();
    void   QP_Remap_RegisterFunction(void* fn, size_t size);
    int    QP_Remap_VerifyIntegrity();
    unsigned int QP_GetTextSectionCrc32();
    unsigned int QP_CalculateCrc32(const void* data, size_t size);
    int    QP_IsFunctionHooked(const void* fn, size_t max_scan);

    int    QP_RegisterPluginBridge(const QP_PluginBridgeDescriptor* desc, QP_PluginContextCallbacks* out_callbacks, void** out_ctx_handle);
    int    QP_UnregisterPluginBridge(const char* plugin_id);
    int    QP_GetPluginCount();
    void   QP_EnablePlugin(const char* plugin_id);
    void   QP_DisablePlugin(const char* plugin_id);
    int    QP_IsPluginEnabled(const char* plugin_id);
    char* QP_SendPluginCustomRequest(const char* action, const char* payload);
}

namespace easyauth {

    enum protection_flags : uint32_t {
        flag_none = 0,
        flag_crc32 = (1 << 0),
        flag_injection_monitor = (1 << 1),
        flag_network_hooks = (1 << 2),
        flag_loader_hooks = (1 << 3),
        flag_manual_map = (1 << 4),
        flag_antidebug = (1 << 5),
        flag_vmp_checks = (1 << 6),
        flag_honeypot = (1 << 7),
        flag_crc32_obf = (1 << 8),
        flag_all = (flag_crc32 | flag_injection_monitor | flag_network_hooks | flag_loader_hooks | flag_manual_map | flag_antidebug | flag_vmp_checks | flag_honeypot)
    };

    struct remote_settings {
      
    };

    struct config {
        uint32_t flags = flag_all;
        uint32_t honeypot_delay_ms = 5000;
        bool vmp_mode = false;
        bool vmp_enforce_protected = false;
        std::string default_api_key = "";
        std::string client_version = "2.0.0";
        uint32_t watchdog_interval_ms = 500;
        std::string hwid_method = "disk";
    };

    struct auth_result {
        bool success = false;
        int error_code = 0;
        std::string error_name;
        std::string message;
        std::string expire_date;
    };

    struct variable_result {
        bool success = false;
        std::string value;
        std::string type;
        std::string error_name;
        std::string message;
    };

    struct file_download_result {
        bool success = false;
        std::string file_name;
        size_t file_size = 0;
        std::vector<uint8_t> data;
        std::string error_name;
        std::string message;
    };

    typedef void (*download_progress_callback)(size_t downloaded_bytes, size_t total_bytes, float percentage);

    struct session_init_result {
        bool success = false;
        std::string error_name;
        std::string message;
    };

    struct map_result {
        bool success = false;
        uint32_t process_id = 0;
        uintptr_t mapped_base = 0;
        std::string error_name;
        std::string message;
    };

#ifdef EASYAUTH_EXPORTS
#define EASYAUTH_API __declspec(dllexport)
#else
#define EASYAUTH_API
#endif

    // Functions
    EASYAUTH_API void initialize();
    EASYAUTH_API void set_config(const config& cfg);
    EASYAUTH_API config get_config();
    EASYAUTH_API remote_settings get_cached_remote_settings();

    EASYAUTH_API bool is_remapped();
    EASYAUTH_API bool is_wiped(void* original_fn);
    EASYAUTH_API void* get_remapped(void* original_fn);
    EASYAUTH_API void register_protected_function(void* fn_ptr, size_t size = 0);

    EASYAUTH_API void enable_protection_flag(protection_flags flag);
    EASYAUTH_API void disable_protection_flag(protection_flags flag);
    EASYAUTH_API bool is_protection_enabled(protection_flags flag);

    typedef const char* (*custom_hwid_generator_fn)();
    EASYAUTH_API void set_custom_hwid(const std::string& hwid);
    EASYAUTH_API void set_custom_hwid_generator(custom_hwid_generator_fn fn);

    EASYAUTH_API session_init_result init_session(const std::string& api_key = "");
    EASYAUTH_API auth_result authenticate(const std::string& key, const std::string& api_key = "");
    EASYAUTH_API auth_result register_computer(const std::string& api_key = "");

    EASYAUTH_API variable_result get_variable_ex(const std::string& access_id, const std::string& key = "", const std::string& api_key = "");
    EASYAUTH_API std::string get_variable(const std::string& access_id, const std::string& key = "", const std::string& api_key = "");

    inline bool is_success(const auth_result& res) { return res.success; }
    inline bool is_success(const variable_result& res) { return res.success; }
    inline bool is_success(const file_download_result& res) { return res.success; }

    EASYAUTH_API file_download_result get_file(const std::string& access_id, const std::string& key = "", const std::string& api_key = "", download_progress_callback progress_cb = nullptr);
    EASYAUTH_API bool download_file_to_disk(const std::string& access_id, const std::string& output_path = "", const std::string& key = "", const std::string& api_key = "", download_progress_callback progress_cb = nullptr);

    EASYAUTH_API map_result server_map(const std::string& access_id, const std::string& target_process, const std::string& key = "", const std::string& api_key = "");

    EASYAUTH_API bool protection_check();
    EASYAUTH_API bool is_hooked(const void* fn_ptr);
    EASYAUTH_API void arm_honeypot(uint32_t delay_ms = 5000);
    EASYAUTH_API bool is_honeypot_armed();
    EASYAUTH_API bool is_injection_detected();
    EASYAUTH_API bool scan_network_hooks();

    EASYAUTH_API bool is_debugger_detected();
    EASYAUTH_API bool hide_thread();
    EASYAUTH_API bool is_virtual_machine();

    EASYAUTH_API std::string capture_screen(void* target_hwnd = nullptr);
    EASYAUTH_API bool report_suspicious(const std::string& reason, const std::string& type = "tamper", bool include_screenshot = false, const std::string& severity = "suspicious", const std::string& api_key = "");
    EASYAUTH_API bool upload_screenshot(const std::string& reason = "routine", const std::string& api_key = "");

    EASYAUTH_API bool scan_and_enforce_remote_blacklists();

    EASYAUTH_API bool is_vmp_protected();
    EASYAUTH_API bool is_vmp_valid_crc();
    EASYAUTH_API bool is_vmp_debugger_present(bool check_kernel = true);

    EASYAUTH_API bool network_connect(const char* host = nullptr, uint16_t port = 0);
    EASYAUTH_API bool network_reconnect();
    EASYAUTH_API bool network_ping(uint32_t& out_latency_ms);
    EASYAUTH_API bool network_test_expired_timestamp(uint32_t seconds_in_past = 120);
    EASYAUTH_API bool network_is_connected();
    EASYAUTH_API void network_disconnect();
    EASYAUTH_API bool network_set_dev_endpoint(const std::string& host, uint16_t port, const std::string& dev_code);

    EASYAUTH_API void start_background_watchdog(uint32_t interval_ms = 500);
    EASYAUTH_API void stop_background_watchdog();
    EASYAUTH_API uint32_t get_background_check_count();

    namespace plugins {

        struct server_response {
            bool success = false;
            int error_code = 0;
            std::string error_name;
            std::string message;
            std::string raw_response_json;
        };

        struct threat_detection {
            bool detected = false;
            std::string threat_name;
            std::string category;
            std::string technical_data;
            int severity = 10;
            bool trigger_mitigation = true;
            bool report_to_server = true;
        };

        enum class auth_event {
            pre_init_session,
            post_init_session,
            pre_authenticate,
            post_authenticate_success,
            post_authenticate_failed,
            watchdog_tick,
            threat_detected,
            shutdown
        };

        struct event_data {
            auth_event event_type;
            const char* api_key = nullptr;
            const char* license_key = nullptr;
            const char* error_message = nullptr;
            const threat_detection* threat = nullptr;
            const remote_settings* settings = nullptr;
        };

        enum plugin_type_flags : uint32_t {
            type_none = 0,
            type_security_detector = (1 << 0),
            type_lifecycle_hook = (1 << 1),
            type_telemetry_provider = (1 << 2),
            type_network_interceptor = (1 << 3),
            type_feature_extension = (1 << 4),
            type_generic = (1 << 5),
            type_all = 0xFFFFFFFF
        };

        struct plugin_info {
            std::string id;
            std::string name;
            std::string version;
            std::string author;
            std::string signature_hash;
            uint32_t type_flags = type_none;
            bool is_critical = false;
        };

        class i_plugin_context {
        public:
            virtual ~i_plugin_context() = default;
            virtual bool is_connected() const = 0;
            virtual bool get_ping(uint32_t& out_latency_ms) = 0;
            virtual server_response send_custom_request(const std::string& action, const std::string& payload_json = "{}") = 0;
            virtual bool send_raw_request(const std::string& full_json_request, std::string& out_resp_payload) = 0;
            virtual std::string get_active_api_key() const = 0;
            virtual std::string get_active_license_key() const = 0;
            virtual const remote_settings& get_remote_settings() const = 0;
            virtual std::string get_server_variable(const std::string& access_id) = 0;
            virtual bool report_threat(const std::string& reason, const std::string& threat_type = "tamper", bool include_screenshot = false) = 0;
            virtual void log_incident(int incident_type, const std::string& details) = 0;
            virtual void trigger_honeypot(uint32_t delay_ms = 0) = 0;
        };

        class i_plugin {
        public:
            virtual ~i_plugin() = default;

            virtual plugin_info get_info() const = 0;

            virtual bool on_initialize(i_plugin_context* context) {
                m_context = context;
                return true;
            }

            virtual void on_shutdown() {
                m_context = nullptr;
            }

            virtual bool on_attach(i_plugin_context* context) { return on_initialize(context); }
            virtual void on_detach() { on_shutdown(); }

            virtual void on_event(const event_data& event) {}
            virtual threat_detection on_security_check(bool deep_scan = false) { return threat_detection{}; }
            virtual void append_telemetry(std::unordered_map<std::string, std::string>& out_telemetry) {}

            virtual bool is_enabled() const { return m_enabled; }
            virtual void set_enabled(bool enabled) { m_enabled = enabled; }

            i_plugin_context* get_context() const { return m_context; }
            void set_context(i_plugin_context* ctx) { m_context = ctx; }

        protected:
            i_plugin_context* m_context = nullptr;
            bool m_enabled = true;
        };
        
        bool register_plugin(std::shared_ptr<i_plugin> plugin);
        bool unregister_plugin(const std::string& plugin_id);
        size_t get_plugin_count();
        std::vector<plugin_info> get_all_plugin_info();
        void enable_plugin(const std::string& plugin_id);
        void disable_plugin(const std::string& plugin_id);
        bool is_plugin_enabled(const std::string& plugin_id);
        server_response send_plugin_custom_request(const std::string& action, const std::string& payload_json = "{}");
        
    } // namespace plugins
    
} // namespace easyauth

namespace qPapelEasyAuth = easyauth;

