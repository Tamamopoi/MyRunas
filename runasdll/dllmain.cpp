
// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include <stdio.h>
#include "detours.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <time.h>
#include "iostream"
#include <algorithm>
using namespace std;
#include "string"
#include "sstream"
#include "fstream"
#pragma comment(lib,"ws2_32.lib")

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")


// AES字符串加密函数 //////////////////////////////////////////////////////////
int TestAesEncryptString(std::string in_string, std::string& out_string, char Key[32])
{
	//用指定密钥对一段内存进行加密，结果放在outbuffer中
	unsigned char aes_keybuf[32];
	memset(aes_keybuf, 0, sizeof(aes_keybuf));
	strcpy((char*)aes_keybuf, Key);

	//创建并初始化ctx对象
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		return -1; //创建失败
	}

	//设置加密参数
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes_keybuf, NULL) != 1) {
		EVP_CIPHER_CTX_free(ctx); //释放ctx对象
		return -2; //设置失败
	}

	//分配内存并进行AES加密
	int len = in_string.length();
	int encrypted_len = 0;
	int final_len = 0;
	unsigned char* encrypted_data = new unsigned char[len + AES_BLOCK_SIZE]; //多分配一个块大小以防止溢出
	if (EVP_EncryptUpdate(ctx, encrypted_data, &encrypted_len, (unsigned char*)in_string.c_str(), len) != 1) {
		delete[] encrypted_data; //释放内存	    
		EVP_CIPHER_CTX_free(ctx); //释放ctx对象	    
		return -3; //加密失败	    
	}
	if (EVP_EncryptFinal_ex(ctx, encrypted_data + encrypted_len, &final_len) != 1) {
		delete[] encrypted_data; //释放内存        
		EVP_CIPHER_CTX_free(ctx); //释放ctx对象        
		return -4; //加密失败        
	}

	encrypted_len += final_len;

	//计算Base64编码后的长度
	int encoded_len = ((encrypted_len + 2) / 3) * 4;

	//分配内存并进行Base64编码
	unsigned char* encoded_data = new unsigned char[encoded_len + 1]; //多分配一个字节以防止溢出
	if (EVP_EncodeBlock(encoded_data, encrypted_data, encrypted_len) != encoded_len) {
		delete[] encoded_data; //释放内存        
		delete[] encrypted_data; //释放内存        
		EVP_CIPHER_CTX_free(ctx); //释放ctx对象        
		return -5; //编码失败        
	}

	out_string.clear();
	out_string.append((char*)encoded_data, encoded_len);

	delete[] encoded_data; //释放内存    
	delete[] encrypted_data; //释放内存    
	EVP_CIPHER_CTX_free(ctx); //释放ctx对象

	return 0;
}


int TestAesDecryptString(std::string encrypted_string, std::string& decrypted_string, char* key) {
	//创建ctx对象
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		return -1; //创建ctx对象失败
	}

	//设置解密参数
	unsigned char iv[16] = { 0 }; //初始化向量，可以自己定义
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, (unsigned char*)key, iv) != 1) { //改成ECB模式，并传入iv参数
		EVP_CIPHER_CTX_free(ctx); //释放ctx对象
		return -2; //设置解密参数失败
	}

	EVP_CIPHER_CTX_set_padding(ctx, 5); //改成PKCS5填充

	//Base64解码
	BIO* b64 = BIO_new(BIO_f_base64());
	BIO* bio = BIO_new_mem_buf(encrypted_string.c_str(), encrypted_string.length());
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	unsigned char* decoded_data = new unsigned char[encrypted_string.length()];
	int decoded_len = BIO_read(bio, decoded_data, encrypted_string.length());
	BIO_free_all(bio);
	if (decoded_len == 0) {
		EVP_CIPHER_CTX_free(ctx); //释放ctx对象
		return -3; //Base64解码失败
	}

	//AES解密
	int decrypted_len = 0;
	int final_len = 0;
	unsigned char* decrypted_data = new unsigned char[decoded_len];
	if (EVP_DecryptUpdate(ctx, decrypted_data, &decrypted_len, decoded_data, decoded_len) != 1) {
		delete[] decrypted_data; //释放内存        
		delete[] decoded_data; //释放内存        
		EVP_CIPHER_CTX_free(ctx); //释放ctx对象        
		return -4; //AES解密失败        
	}
	if (EVP_DecryptFinal_ex(ctx, decrypted_data + decrypted_len, &final_len) != 1) {
		delete[] decrypted_data; //释放内存        
		delete[] decoded_data; //释放内存        
		EVP_CIPHER_CTX_free(ctx); //释放ctx对象        
		return -5; //AES解密失败        
	}

	decrypted_len += final_len;

	std::string temp((char*)decrypted_data);
	temp.resize(decrypted_len);
	delete[] decrypted_data; //释放内存    
	delete[] decoded_data; //释放内存    
	EVP_CIPHER_CTX_free(ctx); //释放ctx对象    
	decrypted_string = temp;
	return 0;
}



typedef BOOL (WINAPI *pfnReadConsole)(
						__in          HANDLE hConsoleInput,
						__out         LPVOID lpBuffer,
						__in          DWORD nNumberOfCharsToRead,
						__out         LPDWORD lpNumberOfCharsRead,
						__in_opt      LPVOID pInputControl
						);


typedef BOOL (WINAPI *pfnCreateProcessWithLogonW)(
									__in          LPCWSTR lpUsername,
									__in          LPCWSTR lpDomain,
									__in          LPCWSTR lpPassword,
									__in          DWORD dwLogonFlags,
									__in          LPCWSTR lpApplicationName,
									__in          LPWSTR lpCommandLine,
									__in          DWORD dwCreationFlags,
									__in          LPVOID lpEnvironment,
									__in          LPCWSTR lpCurrentDirectory,
									__in          LPSTARTUPINFOW lpStartupInfo,
									__out         LPPROCESS_INFORMATION lpProcessInfo
									);




BOOL WINAPI MyReadConsole(
									  __in          HANDLE hConsoleInput,
									  __out         LPVOID lpBuffer,
									  __in          DWORD nNumberOfCharsToRead,
									  __out         LPDWORD lpNumberOfCharsRead,
									  __in_opt      LPVOID pInputControl
									  );


BOOL WINAPI MyCreateProcessWithLogonW(
	__in          LPCWSTR lpUsername,
	__in          LPCWSTR lpDomain,
	__in          LPCWSTR lpPassword,
	__in          DWORD dwLogonFlags,
	__in          LPCWSTR lpApplicationName,
	__in          LPWSTR lpCommandLine,
	__in          DWORD dwCreationFlags,
	__in          LPVOID lpEnvironment,
	__in          LPCWSTR lpCurrentDirectory,
	__in          LPSTARTUPINFOW lpStartupInfo,
	__out         LPPROCESS_INFORMATION lpProcessInfo
	);

BOOL MByteToWChar(LPCSTR lpcszStr, LPWSTR lpwszStr, DWORD dwSize);


pfnReadConsole realReadConsole = (pfnReadConsole)GetProcAddress(LoadLibrary("Kernel32.dll"), "ReadConsoleW");
pfnCreateProcessWithLogonW realCreateProcessWithLogonW = (pfnCreateProcessWithLogonW)GetProcAddress(LoadLibrary("Advapi32.dll"), "CreateProcessWithLogonW");




HANDLE g_hDLL = NULL;




BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	char szModuleName[MAX_PATH] = {0};
	char szExe[MAX_PATH] = {0};
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		g_hDLL = hModule;

		GetModuleFileName(NULL, szModuleName, MAX_PATH-1);		
		strcpy(szExe, strrchr(szModuleName, '\\')+1);

		if (strcmpi(szExe, "RUNAS.EXE"))
		{		
			return TRUE;
		}
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach((PVOID*)&realReadConsole, MyReadConsole);
		DetourAttach((PVOID*)&realCreateProcessWithLogonW, MyCreateProcessWithLogonW);
		DetourTransactionCommit();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}


BOOL WINAPI MyReadConsole(
						  __in          HANDLE hConsoleInput,
						  __out         LPVOID lpBuffer,
						  __in          DWORD nNumberOfCharsToRead,
						  __out         LPDWORD lpNumberOfCharsRead,
						  __in_opt      LPVOID pInputControl
						  )
{
	*((char*)lpBuffer) = 0x0d;
	*lpNumberOfCharsRead = 1;
	return FALSE;
}


BOOL WINAPI MyCreateProcessWithLogonW(
									  __in          LPCWSTR lpUsername,
									  __in          LPCWSTR lpDomain,
									  __in          LPCWSTR lpPassword,
									  __in          DWORD dwLogonFlags,
									  __in          LPCWSTR lpApplicationName,
									  __in          LPWSTR lpCommandLine,
									  __in          DWORD dwCreationFlags,
									  __in          LPVOID lpEnvironment,
									  __in          LPCWSTR lpCurrentDirectory,
									  __in          LPSTARTUPINFOW lpStartupInfo,
									  __out         LPPROCESS_INFORMATION lpProcessInfo
									  )
{	

	WCHAR wcsPassword[128] = {0};	
	char szPassword[128] = {0};
	char szIniFile[MAX_PATH] = {0};	

	std::wstring ws(lpUsername); // 将 LPCWSTR 转换为 std::wstring
	size_t pos = ws.find(L"@"); // 查找 @ 的位置
	if (pos != std::wstring::npos) // 如果找到了 @
	{
		ws = ws.substr(0, pos); // 截取从开头到 @ 位置的子字符串
	}
	std::replace(ws.begin(), ws.end(), L'-', L'='); // 将所有的 "-" 替换为 "="
	lpUsername = ws.c_str(); // 将 std::wstring 转换回 LPCWSTR

	int len = WideCharToMultiByte(CP_ACP, 0, lpUsername, -1, NULL, 0, NULL, NULL); // 获取转换后的长度
	if (len > 128) // 检查长度是否超过数组大小
	{
		std::cout << "Error: lpUsername is too long to fit in szPassword." << std::endl;
	}
	else
	{
		WideCharToMultiByte(CP_ACP, 0, lpUsername, -1, szPassword, len, NULL, NULL); // 将 LPCWSTR 转换为 char 数组
	}

	lpUsername = L"administrator@microsoft.com";//runas的用户名，以上已经获取了密码，所以这里固定写死。


	if (!strlen(szPassword))
	{
		//printf("读取密码文件%s失败，请检查设置是否正确!\n", szIniFile);
		MessageBox(NULL, "读取密码失败，请检查设置是否正确!", "", NULL);
	}
	else
	{
		std::string decrypted_string; // 定义解密后的字符串变量
		char key[32] = "iausohid$!@3e0wd#uijfonso$@#hdw"; // 定义密钥，固定长度。
		//std::string poi; // 定义poi变量
		//poi.clear(); //清空poi变量
		//TestAesEncryptString("WInServer2019.", poi, key); // 调用加密函数，将结果保存在poi中
		//printf(poi.c_str());
		//MessageBox(NULL, poi.c_str(), "加密结果", MB_OK); // 调用MessageBox函数，显示poi的值
		//std::string encrypted_string(szPassword);//转一下str
		//printf(szPassword);

		int ret = TestAesDecryptString(szPassword, decrypted_string, key);

		////用于调试，获取错误代码。
		//if (ret != 0) {
		//	printf("解密失败，错误码: %d\n", ret);
		//	switch (ret) {
		//	case -1:
		//		printf("创建ctx对象失败\n");
		//		break;
		//	case -2:
		//		printf("设置解密参数失败\n");
		//		break;
		//	case -3:
		//		printf("Base64解码失败\n");
		//		break;
		//	case -4:
		//		printf("AES解密失败\n");
		//		break;
		//	case -5:
		//		printf("AES解密结束失败\n");
		//		break;
		//	default:
		//		printf("未知错误\n");
		//	}
		//}
		//else {
		//	printf("解密成功!\n");
		//}


		//MessageBox(NULL, decrypted_string.c_str(), "解密结果", MB_OK); // 调用MessageBox函数，显示poi的值
		strcpy(szPassword, decrypted_string.c_str());
		//printf(szPassword);
		MByteToWChar(szPassword, wcsPassword, sizeof(wcsPassword)/sizeof(wcsPassword[0]));
	}


	//这里是注释。
	//printf("\n");
	//wprintf(lpUsername);
	//printf("\n");
	//wprintf(lpDomain);
	//printf("\n");
	//wprintf(wcsPassword);




	return realCreateProcessWithLogonW(lpUsername,
									   lpDomain,
									   wcsPassword,
									   dwLogonFlags,
									   lpApplicationName,
									   lpCommandLine,
									   dwCreationFlags,
									   lpEnvironment,
									   lpCurrentDirectory,
									   lpStartupInfo,
									   lpProcessInfo);
}


BOOL MByteToWChar(LPCSTR lpcszStr, LPWSTR lpwszStr, DWORD dwSize)
{
	// Get the required size of the buffer that receives the Unicode 
	// string. 
	DWORD dwMinSize;
	dwMinSize = MultiByteToWideChar (CP_ACP, 0, lpcszStr, -1, NULL, 0);

	if(dwSize < dwMinSize)
	{
		return FALSE;
	}

	// Convert headers from ASCII to Unicode.
	MultiByteToWideChar (CP_ACP, 0, lpcszStr, -1, lpwszStr, dwMinSize);  
	return TRUE;
}



//必须要导出任意一个函数，否则会报错
VOID test123()
{
}
