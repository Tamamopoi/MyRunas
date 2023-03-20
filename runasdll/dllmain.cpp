
// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
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


// AES�ַ������ܺ��� //////////////////////////////////////////////////////////
int TestAesEncryptString(std::string in_string, std::string& out_string, char Key[32])
{
	//��ָ����Կ��һ���ڴ���м��ܣ��������outbuffer��
	unsigned char aes_keybuf[32];
	memset(aes_keybuf, 0, sizeof(aes_keybuf));
	strcpy((char*)aes_keybuf, Key);

	//��������ʼ��ctx����
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		return -1; //����ʧ��
	}

	//���ü��ܲ���
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes_keybuf, NULL) != 1) {
		EVP_CIPHER_CTX_free(ctx); //�ͷ�ctx����
		return -2; //����ʧ��
	}

	//�����ڴ沢����AES����
	int len = in_string.length();
	int encrypted_len = 0;
	int final_len = 0;
	unsigned char* encrypted_data = new unsigned char[len + AES_BLOCK_SIZE]; //�����һ�����С�Է�ֹ���
	if (EVP_EncryptUpdate(ctx, encrypted_data, &encrypted_len, (unsigned char*)in_string.c_str(), len) != 1) {
		delete[] encrypted_data; //�ͷ��ڴ�	    
		EVP_CIPHER_CTX_free(ctx); //�ͷ�ctx����	    
		return -3; //����ʧ��	    
	}
	if (EVP_EncryptFinal_ex(ctx, encrypted_data + encrypted_len, &final_len) != 1) {
		delete[] encrypted_data; //�ͷ��ڴ�        
		EVP_CIPHER_CTX_free(ctx); //�ͷ�ctx����        
		return -4; //����ʧ��        
	}

	encrypted_len += final_len;

	//����Base64�����ĳ���
	int encoded_len = ((encrypted_len + 2) / 3) * 4;

	//�����ڴ沢����Base64����
	unsigned char* encoded_data = new unsigned char[encoded_len + 1]; //�����һ���ֽ��Է�ֹ���
	if (EVP_EncodeBlock(encoded_data, encrypted_data, encrypted_len) != encoded_len) {
		delete[] encoded_data; //�ͷ��ڴ�        
		delete[] encrypted_data; //�ͷ��ڴ�        
		EVP_CIPHER_CTX_free(ctx); //�ͷ�ctx����        
		return -5; //����ʧ��        
	}

	out_string.clear();
	out_string.append((char*)encoded_data, encoded_len);

	delete[] encoded_data; //�ͷ��ڴ�    
	delete[] encrypted_data; //�ͷ��ڴ�    
	EVP_CIPHER_CTX_free(ctx); //�ͷ�ctx����

	return 0;
}


int TestAesDecryptString(std::string encrypted_string, std::string& decrypted_string, char* key) {
	//����ctx����
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		return -1; //����ctx����ʧ��
	}

	//���ý��ܲ���
	unsigned char iv[16] = { 0 }; //��ʼ�������������Լ�����
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, (unsigned char*)key, iv) != 1) { //�ĳ�ECBģʽ��������iv����
		EVP_CIPHER_CTX_free(ctx); //�ͷ�ctx����
		return -2; //���ý��ܲ���ʧ��
	}

	EVP_CIPHER_CTX_set_padding(ctx, 5); //�ĳ�PKCS5���

	//Base64����
	BIO* b64 = BIO_new(BIO_f_base64());
	BIO* bio = BIO_new_mem_buf(encrypted_string.c_str(), encrypted_string.length());
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	unsigned char* decoded_data = new unsigned char[encrypted_string.length()];
	int decoded_len = BIO_read(bio, decoded_data, encrypted_string.length());
	BIO_free_all(bio);
	if (decoded_len == 0) {
		EVP_CIPHER_CTX_free(ctx); //�ͷ�ctx����
		return -3; //Base64����ʧ��
	}

	//AES����
	int decrypted_len = 0;
	int final_len = 0;
	unsigned char* decrypted_data = new unsigned char[decoded_len];
	if (EVP_DecryptUpdate(ctx, decrypted_data, &decrypted_len, decoded_data, decoded_len) != 1) {
		delete[] decrypted_data; //�ͷ��ڴ�        
		delete[] decoded_data; //�ͷ��ڴ�        
		EVP_CIPHER_CTX_free(ctx); //�ͷ�ctx����        
		return -4; //AES����ʧ��        
	}
	if (EVP_DecryptFinal_ex(ctx, decrypted_data + decrypted_len, &final_len) != 1) {
		delete[] decrypted_data; //�ͷ��ڴ�        
		delete[] decoded_data; //�ͷ��ڴ�        
		EVP_CIPHER_CTX_free(ctx); //�ͷ�ctx����        
		return -5; //AES����ʧ��        
	}

	decrypted_len += final_len;

	std::string temp((char*)decrypted_data);
	temp.resize(decrypted_len);
	delete[] decrypted_data; //�ͷ��ڴ�    
	delete[] decoded_data; //�ͷ��ڴ�    
	EVP_CIPHER_CTX_free(ctx); //�ͷ�ctx����    
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

	std::wstring ws(lpUsername); // �� LPCWSTR ת��Ϊ std::wstring
	size_t pos = ws.find(L"@"); // ���� @ ��λ��
	if (pos != std::wstring::npos) // ����ҵ��� @
	{
		ws = ws.substr(0, pos); // ��ȡ�ӿ�ͷ�� @ λ�õ����ַ���
	}
	std::replace(ws.begin(), ws.end(), L'-', L'='); // �����е� "-" �滻Ϊ "="
	lpUsername = ws.c_str(); // �� std::wstring ת���� LPCWSTR

	int len = WideCharToMultiByte(CP_ACP, 0, lpUsername, -1, NULL, 0, NULL, NULL); // ��ȡת����ĳ���
	if (len > 128) // ��鳤���Ƿ񳬹������С
	{
		std::cout << "Error: lpUsername is too long to fit in szPassword." << std::endl;
	}
	else
	{
		WideCharToMultiByte(CP_ACP, 0, lpUsername, -1, szPassword, len, NULL, NULL); // �� LPCWSTR ת��Ϊ char ����
	}

	lpUsername = L"administrator@microsoft.com";//runas���û����������Ѿ���ȡ�����룬��������̶�д����


	if (!strlen(szPassword))
	{
		//printf("��ȡ�����ļ�%sʧ�ܣ����������Ƿ���ȷ!\n", szIniFile);
		MessageBox(NULL, "��ȡ����ʧ�ܣ����������Ƿ���ȷ!", "", NULL);
	}
	else
	{
		std::string decrypted_string; // ������ܺ���ַ�������
		char key[32] = "iausohid$!@3e0wd#uijfonso$@#hdw"; // ������Կ���̶����ȡ�
		//std::string poi; // ����poi����
		//poi.clear(); //���poi����
		//TestAesEncryptString("WInServer2019.", poi, key); // ���ü��ܺ����������������poi��
		//printf(poi.c_str());
		//MessageBox(NULL, poi.c_str(), "���ܽ��", MB_OK); // ����MessageBox��������ʾpoi��ֵ
		//std::string encrypted_string(szPassword);//תһ��str
		//printf(szPassword);

		int ret = TestAesDecryptString(szPassword, decrypted_string, key);

		////���ڵ��ԣ���ȡ������롣
		//if (ret != 0) {
		//	printf("����ʧ�ܣ�������: %d\n", ret);
		//	switch (ret) {
		//	case -1:
		//		printf("����ctx����ʧ��\n");
		//		break;
		//	case -2:
		//		printf("���ý��ܲ���ʧ��\n");
		//		break;
		//	case -3:
		//		printf("Base64����ʧ��\n");
		//		break;
		//	case -4:
		//		printf("AES����ʧ��\n");
		//		break;
		//	case -5:
		//		printf("AES���ܽ���ʧ��\n");
		//		break;
		//	default:
		//		printf("δ֪����\n");
		//	}
		//}
		//else {
		//	printf("���ܳɹ�!\n");
		//}


		//MessageBox(NULL, decrypted_string.c_str(), "���ܽ��", MB_OK); // ����MessageBox��������ʾpoi��ֵ
		strcpy(szPassword, decrypted_string.c_str());
		//printf(szPassword);
		MByteToWChar(szPassword, wcsPassword, sizeof(wcsPassword)/sizeof(wcsPassword[0]));
	}


	//������ע�͡�
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



//����Ҫ��������һ������������ᱨ��
VOID test123()
{
}
