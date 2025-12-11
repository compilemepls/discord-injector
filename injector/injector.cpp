#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <chrono>
#include <iomanip>
#include <csignal>
#include <windows.h>
#include <tlhelp32.h>
#include <ctime>
#include <thread>
#include <shellapi.h>

#pragma comment(lib, "shell32.lib")

using namespace std;

bool run = true;
void Sig(int) { run = false; }

struct H {
    HANDLE h;
    H(HANDLE _h) : h(_h) {}
    ~H() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    operator HANDLE() { return h; }
    bool ok() { return h && h != INVALID_HANDLE_VALUE; }
};

string Rnd(int len) {
    string s;
    const char c[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for (int i = 0; i < len; i++) s += c[rand() % (sizeof(c) - 1)];
    return s;
}

void Log(wstring tag, wstring msg) {
    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hCon, 7);
    auto t = chrono::system_clock::to_time_t(chrono::system_clock::now());
    wcout << L"[" << put_time(localtime(&t), L"%T") << L"] [";
    SetConsoleTextAttribute(hCon, 13);
    wcout << tag;
    SetConsoleTextAttribute(hCon, 7);
    wcout << L"] " << msg << endl;
}

void clean_old(string path) {
    for (int i = 0; i < 50; i++) {
        if (DeleteFileA(path.c_str())) break;
        Sleep(100);
    }
}

string find_dll(string dir) {
    WIN32_FIND_DATAA fd;
    string search = dir + "\\*.dll";
    HANDLE h = FindFirstFileA(search.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return "";
    string name = fd.cFileName;
    FindClose(h);
    return name;
}

void Morph() {
    char p[MAX_PATH];
    GetModuleFileNameA(0, p, MAX_PATH);
    string curExe(p);
    string dir = curExe.substr(0, curExe.find_last_of("\\/"));

    string dllName = find_dll(dir);
    if (dllName.empty()) {
        cout << "No DLL found in current directory." << endl;
        system("pause");
        exit(1);
    }

    string curDll = dir + "\\" + dllName;

    char tmp[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);

    string subDir = string(tmp) + Rnd(16);
    CreateDirectoryA(subDir.c_str(), 0);

    string newExe = subDir + "\\" + Rnd(8) + ".exe";
    string newDll = subDir + "\\" + Rnd(8) + ".dll";

    if (CopyFileA(curExe.c_str(), newExe.c_str(), 0)) {
        if (MoveFileA(curDll.c_str(), newDll.c_str())) {
            string args = "\"" + newDll + "\" \"" + curExe + "\"";
            ShellExecuteA(0, "open", newExe.c_str(), args.c_str(), 0, SW_SHOW);
            exit(0);
        }
    }
}

void tloop() {
    const char c[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*();'[]";
    while (run) {
        string s;
        for (int i = 0; i < 64; i++) s += c[rand() % (sizeof(c) - 1)];
        SetConsoleTitleA(s.c_str());
        Sleep(1);
    }
}

void Banner() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(h, 5);
    const char* art = R"(
  _____  ______ _______ _____   ____  
 |  __ \|  ____|__   __|  __ \ / __ \ 
 | |__) | |__     | |  | |__) | |  | |
 |  _  /|  __|    | |  |  _  /| |  | |
 | | \ \| |____   | |  | | \ \| |__| |
 |_|  \_\______|  |_|  |_|  \_\\____/ 
  _____ _   _      _ ______ _____ _______ ____  _____  
 |_   _| \ | |    | |  ____/ ____|__   __/ __ \|  __ \ 
   | | |  \| |    | | |__ | |       | | | |  | | |__) |
   | | | . ` |_   | |  __|| |       | | | |  | |  _  / 
  _| |_| |\  | |__| | |___| |____   | | | |__| | | \ \ 
 |_____|_| \_|\____/|______\_____|  |_|  \____/|_|  \_\
)";
    for (int i = 0; art[i] != 0; i++) {
        cout << art[i];
        if (art[i] != ' ') Sleep(1);
    }
    cout << endl;
    SetConsoleTextAttribute(h, 7);
}

vector<DWORD> Get(wstring n) {
    vector<DWORD> v;
    H s(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!s.ok()) return v;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(s, &pe)) {
        do { if (!_wcsicmp(pe.szExeFile, n.c_str())) v.push_back(pe.th32ProcessID); } while (Process32NextW(s, &pe));
    }
    return v;
}

bool Inj(DWORD pid, string p) {
    H h(OpenProcess(PROCESS_ALL_ACCESS, 0, pid));
    if (!h.ok()) return 0;

    wstring wp(p.begin(), p.end());
    size_t z = (wp.size() + 1) * 2;
    void* m = VirtualAllocEx(h, 0, z, MEM_COMMIT, PAGE_READWRITE);
    if (!m) return 0;

    if (!WriteProcessMemory(h, m, wp.c_str(), z, 0)) {
        VirtualFreeEx(h, m, 0, MEM_RELEASE);
        return 0;
    }

    HMODULE hk = GetModuleHandleW(L"kernel32.dll");
    if (!hk) { VirtualFreeEx(h, m, 0, MEM_RELEASE); return 0; }

    void* lb = (void*)GetProcAddress(hk, "LoadLibraryW");
    if (!lb) { VirtualFreeEx(h, m, 0, MEM_RELEASE); return 0; }

    H t(CreateRemoteThread(h, 0, 0, (LPTHREAD_START_ROUTINE)lb, m, 0, 0));

    if (!t.ok()) { VirtualFreeEx(h, m, 0, MEM_RELEASE); return 0; }

    WaitForSingleObject(t, INFINITE);
    VirtualFreeEx(h, m, 0, MEM_RELEASE);
    return 1;
}

int main(int argc, char* argv[]) {
    srand((unsigned)time(0));

    if (argc < 2) {
        Morph();
        return 0;
    }

    string dllPath = argv[1];

    if (argc >= 3) {
        thread(clean_old, string(argv[2])).detach();
    }

    thread(tloop).detach();
    Banner();
    signal(SIGINT, Sig);

    if (GetFileAttributesA(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        Log(L"ERR", L"DLL Missing");
        system("pause");
        return 1;
    }

    vector<wstring> list = { L"discord.exe", L"discordptb.exe", L"discordcanary.exe", L"retrocord.exe" };
    wcout << L" Select Target:\n";
    for (size_t i = 0; i < list.size(); ++i) wcout << L" [" << i + 1 << L"] " << list[i] << endl;

    size_t c = 0;
    while (1) {
        wcout << L"\n > ";
        string s; getline(cin, s);
        try { if ((c = stoul(s)) >= 1 && c <= list.size()) break; }
        catch (...) {}
    }

    wstring exe = list[c - 1];
    Log(L"INIT", L"Waiting for " + exe);
    set<DWORD> h;

    while (run) {
        for (DWORD pid : Get(exe)) {
            if (h.find(pid) == h.end()) {
                Log(L"INFO", L"Found PID " + to_wstring(pid));
                if (Inj(pid, dllPath)) { Log(L"OK", L"Injected successfully"); h.insert(pid); }
                else Log(L"FAIL", L"Injection failed");
            }
        }
        for (auto i = h.begin(); i != h.end();) {
            H p(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, *i));
            DWORD x;
            if (!p.ok() || (GetExitCodeProcess(p, &x) && x != STILL_ACTIVE)) {
                Log(L"EXIT", L"PID " + to_wstring(*i) + L" ended");
                i = h.erase(i);
            }
            else ++i;
        }
        Sleep(1500);
    }
    return 0;
}