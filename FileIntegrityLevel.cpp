// compile command:
// -lAdvapi32 -static
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <cstdio>
#include <string>
#include <vector>
#include <algorithm>

// 辅助函数：不区分大小写的字符串比较
bool IsArg(const std::string& input, const std::string& shortCmd, const std::string& longCmd) {
    std::string copy = input;
    std::transform(copy.begin(), copy.end(), copy.begin(), ::toupper);
    
    std::string sCmd = shortCmd;
    std::transform(sCmd.begin(), sCmd.end(), sCmd.begin(), ::toupper);
    
    std::string lCmd = longCmd;
    std::transform(lCmd.begin(), lCmd.end(), lCmd.begin(), ::toupper);

    return (copy == sCmd || copy == lCmd);
}

// ---------------------------------------------------------
// 功能 1: 查看文件完整性级别
// ---------------------------------------------------------
void GetFileIntegrityLevel(LPCSTR lpFileName) {
    DWORD dwError = ERROR_SUCCESS;
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pSacl = NULL;
    
    // 获取 SACL 信息 (使用 A 版本 API)
    dwError = GetNamedSecurityInfoA(
        lpFileName,
        SE_FILE_OBJECT,
        LABEL_SECURITY_INFORMATION, // 请求完整性标签
        NULL, NULL, NULL,
        &pSacl,
        &pSD
    );

    if (dwError != ERROR_SUCCESS) {
        printf("[-] 获取安全信息失败。错误代码: %lu\n", dwError);
        return;
    }

    if (pSacl == NULL) {
        // 如果没有 SACL，通常意味着默认的 Medium
        printf("[*] 完整性级别: 中 (Medium) [默认/隐式]\n");
        if (pSD) LocalFree(pSD);
        return;
    }

    // 遍历 SACL 查找 Label ACE
    bool found = false;
    for (DWORD i = 0; i < pSacl->AceCount; i++) {
        PSYSTEM_MANDATORY_LABEL_ACE pAce = NULL;
        if (GetAce(pSacl, i, (LPVOID*)&pAce)) {
            if (pAce->Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
                found = true;
                
                // 1. 解析级别 (SID Sub Authority)
                PSID pSid = (PSID)(&pAce->SidStart);
                PDWORD pRid = GetSidSubAuthority(pSid, *GetSidSubAuthorityCount(pSid) - 1);
                DWORD rid = *pRid;

                const char* levelName = "";
                switch (rid) {
                    case SECURITY_MANDATORY_LOW_RID:    levelName = "低 (Low)"; break;
                    case SECURITY_MANDATORY_MEDIUM_RID: levelName = "中 (Medium)"; break;
                    case SECURITY_MANDATORY_HIGH_RID:   levelName = "高 (High)"; break;
                    case SECURITY_MANDATORY_SYSTEM_RID: levelName = "系统 (System)"; break;
                    case SECURITY_MANDATORY_PROTECTED_PROCESS_RID: levelName = "受保护 (Protected)"; break;
                    case SECURITY_MANDATORY_UNTRUSTED_RID: levelName = "不可信 (Untrusted)"; break;
                    default: 
                        // 处理未知 RID 的格式化输出
                        char unknownBuf[64];
                        sprintf(unknownBuf, "未知 (0x%lu)", rid);
                        levelName = unknownBuf;
                        break;
                }

                // 2. 解析策略 (Mask)
                char policies[128] = "";
                DWORD mask = pAce->Mask;
                if (mask & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP)   strcat_s(policies, " [禁止向上写入]");
                if (mask & SYSTEM_MANDATORY_LABEL_NO_READ_UP)    strcat_s(policies, " [禁止向上读取]");
                if (mask & SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP) strcat_s(policies, " [禁止向上执行]");
                if (strlen(policies) == 0) strcpy_s(policies, " [无特殊策略]");

                printf("[*] 文件: %s\n", lpFileName);
                printf("[*] 完整性级别: %s\n", levelName);
                printf("[*] 强制策略:  %s\n", policies);
                break; // 通常只有一个 Label ACE
            }
        }
    }

    if (!found) {
        printf("[*] 完整性级别: 中 (Medium) [未找到显式ACE，默认为中]\n");
    }

    if (pSD) LocalFree(pSD);
}

// ---------------------------------------------------------
// 功能 2: 设置文件完整性级别
// ---------------------------------------------------------
bool SetFileIntegrityLevel(LPCSTR lpFileName, const std::string& levelStr, const std::string& policyStr) {
    // 映射用户输入到 SDDL ID
    std::string sddlLevel;
    
    if (IsArg(levelStr, "U", "Untrusted")) sddlLevel = "S-1-16-0";// Untrusted
    else if (IsArg(levelStr, "L", "LOW")) sddlLevel = "LW";      // Low
    else if (IsArg(levelStr, "M", "Medium")) sddlLevel = "ME"; // Medium
    else if (IsArg(levelStr, "H", "High")) sddlLevel = "HI"; // High
    else if (IsArg(levelStr, "S", "System")) sddlLevel = "SI"; // System
    else if (IsArg(levelStr, "P", "Protected")) sddlLevel = "S-1-16-20480";// Protected 
    else sddlLevel = levelStr;

    // 构造 SDDL 字符串
    // 默认加上 NW (NoWriteUp) 符合大多数安全场景
    std::string finalPolicy = policyStr;
    
    std::string sddlString = "S:(ML;;" + finalPolicy + ";;;" + sddlLevel + ")";
    
    printf("[*] 应用 SDDL: %s\n", sddlString.c_str());

    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pSacl = NULL;
    BOOL fSaclPresent = FALSE;
    BOOL fSaclDefaulted = FALSE;

    // 使用 A 版本 API
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            sddlString.c_str(), SDDL_REVISION_1, &pSD, NULL)) {
        printf("[-] SDDL 转换失败。错误代码: %lu\n", GetLastError());
        return false;
    }

    if (!GetSecurityDescriptorSacl(pSD, &fSaclPresent, &pSacl, &fSaclDefaulted)) {
        printf("[-] 从 SD 获取 SACL 失败。错误代码: %lu\n", GetLastError());
        LocalFree(pSD);
        return false;
    }

    // 使用 A 版本 API
    DWORD dwError = SetNamedSecurityInfoA(
        (LPSTR)lpFileName,
        SE_FILE_OBJECT,
        LABEL_SECURITY_INFORMATION,
        NULL, NULL, NULL,
        pSacl
    );

    LocalFree(pSD);

    if (dwError != ERROR_SUCCESS) {
        printf("[-] 设置安全信息失败。错误代码: %lu\n", dwError);
        if (dwError == 5) printf("    (拒绝访问: 请尝试以管理员身份运行此程序)\n");
        return false;
    }

    printf("[+] 成功修改完整性级别。\n");
    return true;
}

void PrintUsage() {
    printf("用法:\n");
    printf("  查看级别: FileIntegrityLevel.exe <文件路径>\n");
    printf("  设置级别: FileIntegrityLevel.exe <文件路径> <级别> [策略标志...]\n");
    printf("\n级别 (Level):\n");
    printf("  U, Untrusted 不可信完整性 (极其受限)\n");
    printf("  L, Low       低完整性 (受限)\n");
    printf("  M, Medium    中完整性 (默认)\n");
    printf("  H, High      高完整性 (需要管理员)\n");
    printf("  S, System    系统完整性 (需要 System)\n");
    printf("  P, Protected 受保护完整性 (需要 System)\n");
    printf("\n策略标志 (Flags):\n");
    printf("  -NW, -NoWriteUp    禁止低级别进程写入 (不会默认打开)\n");
    printf("  -NR, -NoReadUp     禁止低级别进程读取\n");
    printf("  -NE, -NoExecuteUp  禁止低级别进程执行\n");
    printf("\n示例:\n");
    printf("  FileIntegrityLevel.exe test.txt Low -NW -NR\n");
}

int main(int argc, char* argv[]) {

    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    LPCSTR filePath = argv[1];

    // 模式 1: 查看级别
    if (argc == 2) {
        GetFileIntegrityLevel(filePath);
        return 0;
    }

    // 模式 2: 设置级别
    std::string levelArg = argv[2];
    std::string policyMask = ""; 

    // 解析后续标志参数
    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        
        if (IsArg(arg, "-NW", "-NoWriteUp")) {
            policyMask += "NW";
        } else if (IsArg(arg, "-NR", "-NoReadUp")) {
            policyMask += "NR";
        } else if (IsArg(arg, "-NE", "-NoExecuteUp")) {
            policyMask += "NX"; // SDDL 中用 NX 表示 NoExecute
        } else {
            printf("[!] 忽略未知参数: %s\n", arg.c_str());
        }
    }

    SetFileIntegrityLevel(filePath, levelArg, policyMask);

    return 0;
}