---
layout: post
title: powershell witouth powershell.exe
date: 2026-05-15
description: Unmanaged Powershell
categories: windows redteam
tags: windows redteam
---

* content
{:toc}








# Unmanaged PowerShell


Unmanaged PowerShell se refere a tecnica de executar powershell sem usar o binario ```powershell.exe```. Isso é possivel porque o core do powershell não está no exe e sim na dll ```System.Management.Automation.dll``` aka ```core assembly of Powershell``` (como diz a documentação da microsoft). Basicamente, powershell.exe carrega o assembly ```System.Management.Automation``` e usa as funções que tem nele para invocar comandos powershell.

Então isso significa que qualquer linguagem pode usar essa dll e executar comandos powershell?? A resposta curta é talvez, com alguma dificuldade extra, ja que é nativamente feita pra .net + csharp, o mais apropriado seria essa stack, você pode criar seu programa c# que referência o assembly System.Management.Automation e executar powershell (igual [SharpPick](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerPick/SharpPick/Program.cs) faz), porém, também pode ser usada atraves de c/c++ que veremos mais adiante.

Outra coisa importante é a parte do ```Unmanaged``` que se refere a como um código é executado no s.o. Para entender isso vou resumir a diferença entre ```Managed``` e ```Unmanaged``` code.

O ```Managed``` code é um código que roda em cima de um ```Runtime```, no caso do csharp esse runtime é o ```CLR``` (Common Language Runtime) do .net. O CLR é reponsavel por compilar o source code convertido em ```byte code``` para uma "intermediate language" da microsoft aka ```MSIL``` (Microsotf Intermediate Language) e depois disso essa IL é compilada pelo ```JIT``` (Just In Time Compiler), só então o código é executado, e tudo isso é feito quando o binario é executado.


Agora o ```Unmanaged``` é executado direto pelo s.o. Por exemplo os binarios c/c++ que são compilados uma vez para o ```binary format``` e são executados com ```assembly``` tendo acesso direto a cpu e memória.

Resumindo o managed depende de um runtime e o unmanaged não.

- managed vs unmanaged

![mvcu](/img/mvcu.png)


- .Net CLR

![mvcu2](/img/mvcu2.png)



- Ok, sabemos que "Powershell" é diferente de "powershell.exe" e a diferença de "managed" e "unmanaged" code, agora precisamos saber como isso funciona, como podemos tirar vantagem disso e etc etc etc...

Para isso ficar mais claro é necessario entender a ideia de [Unmanaged Powershell](https://github.com/leechristensen/UnmanagedPowerShell), segundo o autor (Lee Christensen) a ideia é executar um custom powershell assembly c#/.net na memória de qualquer processo "unmanaged" sem spawnar powershell.exe, isso evitaria "triggar" soluções de segurança que monitoram execução de powershell.

Considerando que programas c#/.net rodam em cima do CLR runtime (managed code), pra que essa tecnica seja possivel é necessario iniciar esse runtime na memória do processo e depois carregar e rodar custom powershell assembly. 

Felizmente a microsoft oferece interfaces que possibilitam essa integração de apps unmanaged com o CLR [https://learn.microsoft.com/en-us/dotnet/framework/unmanaged-api/](https://learn.microsoft.com/en-us/dotnet/framework/unmanaged-api/). A principal funcionalidade que permite essa integração é chamada de ```Interoperability``` ou ```COM Interop``` facilitando a "comunicação" entre c++ e .net.

- [https://learn.microsoft.com/en-us/dotnet/standard/native-interop/cominterop](https://learn.microsoft.com/en-us/dotnet/standard/native-interop/cominterop)
- [https://learn.microsoft.com/en-us/dotnet/csharp/advanced-topics/interop/](https://learn.microsoft.com/en-us/dotnet/csharp/advanced-topics/interop/)

Sobre essa parte confesso que não me aprofundei muito por ter um conteudo denso e eu ficaria muito tempo pra entender detalhadamente como essa intergração de c++ e c# funciona, então não espere algo como um "deep dive" sobre isso, mas vou deixar referências que achei pra quem quiser se aprofundar [https://medium.com/@maximiliysiss/c-calls-c-a-tale-of-friendship-across-runtimes-0168d679f66d](https://medium.com/@maximiliysiss/c-calls-c-a-tale-of-friendship-across-runtimes-0168d679f66d). Na parte que vamos destrinchar o código veremos um pouco de como funciona.


- Qual é a vantagem disso?

Bom, a vantagem principal é a Evasão de Defesas como AMSI, Script Blocking Logging, AppLocker e Contrained Language Mode. Todas essas defesas impedem ou monitoram a execução de powershell sendo uma pedra no caminho para executar ferramentas powershell de pós-exploração porque a maioria delas spawnam processos powershell.exe e são pegos na hora.

Essa não é a unica ferramenta que executa a tecnica, também temos o conjunto [PowerPick](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) que é integrado ao framework de post-exp Empire, amplamente conhecido. No conjunto temos 3 ferramentas PSInjector, ReflectivePick e SharpPick, que fazem basicamente a mesma coisa, injetam um assembly customizado na memória para executar powershell.



- https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick
- https://web.archive.org/20160327101330/http://www.sixdub.net/?p=367
- https://itm4n.github.io/reinventing-powershell/


# Unmanaged Powershell Code

Depois de uma introdução ao tema vamos ver como é o código. O foco vai ser nesse projeto que é o mais conhecido [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell).

O projeto é dividido da seguinte forma:

```sh
└─$ tree
.
├── PowerShellRunner                   <===== custom PS code c#/.net 
│   ├── PowerShellRunner.cs                   que será carregado em memória
│   ├── PowerShellRunner.csproj
│   ├── Properties
│   │   └── AssemblyInfo.cs
│   └── System.Management.Automation.dll
| 
├── UnmanagedPowerShell
│   ├── PowerShellRunnerDll.h         <===== .net code convertido em byte-code
│   ├── ReadMe.txt
│   ├── stdafx.cpp
│   ├── stdafx.h
│   ├── targetver.h
│   ├── UnmanagedPowerShell.cpp        <===== c++ core code que carrega em memória
│   ├── UnmanagedPowerShell.vcxproj           o .net byte-code e o CLR runtime
│   └── UnmanagedPowerShell.vcxproj.filters
└── UnmanagedPowerShell.sln
```

O fluxo de execução funciona assim, ```UnmanagedPowerShell.cpp``` contem o header file ```PowerShellRunnerDll.h```, esse header file contem o byte-code da dll que é gerada a partir do custom powershell runner, então o c++ core carrega o .net runtime em memória e logo depois o custom powershell em si.

## UnmanagedPowerShell.cpp main function part 1

Esse não é um código muito complicado mas tem algumas camadas e não reune tudo num arquivo só, então vou seguir o fluxo de execução da função ```_tmain``` e acompanhar as chamadas que ela faz.


```cpp
int _tmain(int argc, _TCHAR* argv[])
{
	HRESULT hr;
	ICorRuntimeHost *pCorRuntimeHost = NULL;
	IUnknownPtr spAppDomainThunk = NULL;
	_AppDomainPtr spDefaultAppDomain = NULL;

	// The .NET assembly to load.
	bstr_t bstrAssemblyName("PowerShellRunner");
	_AssemblyPtr spAssembly = NULL;

	// The .NET class to instantiate.
	bstr_t bstrClassName("PowerShellRunner.PowerShellRunner");
	_TypePtr spType = NULL;
```


No inicio da main algumas definições de variaveis importantes, a primeira delas é ```HRESULT hr``` que recebe um "status code" das COM API calls.

A segunda é ```ICorRuntimeHost *pCorRuntimeHost``` que recebe uma interface ```ICorRuntimeHost``` com metodos que permitem iniciar/parar o CLR em um host. ``` Na nomeclatura da microsoft um HOST significa o processo que recebe o .net CLR ```

As outras são ```IUnknownPtr spAppDomainThun``` e ```_AppDomainPtr spDefaultAppDomain``` que vão receber ponteiros para o ```AppDomain``` que são o ```namespace``` e ```class``` do ```PowerShellRunner.cs``` para depois serem chamas e executadas...



```cpp
// Create the runtime host
	if (createHost(L"v4.0.30319", &pCorRuntimeHost)) {
		wprintf(L"Failed to create the runtime host\n");
		goto Cleanup;
	}

	// Start the CLR
	hr = pCorRuntimeHost->Start();
	if (FAILED(hr)) {
		wprintf(L"CLR failed to start w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}
```


Em seguida temos uma chamada a função ```createHost()``` responsavel por carregar a lib ```mscoree.dll``` que possui as funções core para CLR Hosting. Ela recebe a versão e uma variavel que vai receber os metodos da interface para então iniciar o CLR runtime no processo com ```pCorRuntimeHost->Start();```.

A funcão ```createHost``` passa a execução para outras duas funções ```createDotNetFourHost()``` e ```createDotNetTwoHost()```. A logica aqui é a seguinte: se o host v4 ou v2 for criado o fluxo continua. Para criar o host é usado primeiro a função ```CLRCreateInstance()``` resolvida direto do handle da ```mscoree.dll```, que libera mais metodos para serem usados.

Um deles é o ```ICLRMetaHost``` usado para especificar a versão do CLR runtime a ser iniciado. Depois verifica se a versão especificada pode ser carregada, se não, tenta outra versão ou encerra a execução.

Se o runtime puder ser carregado então chama ```ICLRRuntimeInfo()``` com o metodo ```GetInterface()``` para fazer isso e retorna  a runtime interface (CorRuntimeHost).

- https://learn.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/clrcreateinstance-function
- https://learn.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/iclrmetahost-getruntime-method
- https://learn.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/iclrruntimeinfo-getinterface-method



```cpp
bool createDotNetFourHost(HMODULE* hMscoree, const wchar_t* version, ICorRuntimeHost** ppCorRuntimeHost)
{
	HRESULT hr = NULL;
	funcCLRCreateInstance pCLRCreateInstance = NULL;
	ICLRMetaHost *pMetaHost = NULL;
	ICLRRuntimeInfo *pRuntimeInfo = NULL;
	bool hostCreated = false;

	pCLRCreateInstance = (funcCLRCreateInstance)GetProcAddress(*hMscoree, "CLRCreateInstance");
	if (pCLRCreateInstance == NULL)
	{
		wprintf(L"Could not find .NET 4.0 API CLRCreateInstance");
		goto Cleanup;
	}

	hr = pCLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMetaHost));
	if (FAILED(hr))
	{
		// Potentially fails on .NET 2.0/3.5 machines with E_NOTIMPL
		wprintf(L"CLRCreateInstance failed w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	hr = pMetaHost->GetRuntime(L"v4.0.30319", IID_PPV_ARGS(&pRuntimeInfo));
	if (FAILED(hr))
	{
		wprintf(L"ICLRMetaHost::GetRuntime failed w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Check if the specified runtime can be loaded into the process.
	BOOL loadable;
	hr = pRuntimeInfo->IsLoadable(&loadable);
	if (FAILED(hr))
	{
		wprintf(L"ICLRRuntimeInfo::IsLoadable failed w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	if (loadable)
	{
		wprintf(L".NET runtime v2.0.50727 cannot be loaded\n");
		goto Cleanup;
	}

	// Load the CLR into the current process and return a runtime interface
	hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_PPV_ARGS(ppCorRuntimeHost));
	if (FAILED(hr))
	{
		wprintf(L"ICLRRuntimeInfo::GetInterface failed w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	hostCreated = true;
```



## UnmanagedPowerShell.cpp main function part 2

Seguindo o restante da main, com a interface CorRuntimeHost criada temos acesso aos metodos dela. 

```GetDefaultDomain``` faz referencia ao AppDomain a ser carregado, depois chama ```QueryInterface``` para obter uma interface para o AppDomain.

- https://learn.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/icorruntimehost-getdefaultdomain-method
- https://learn.microsoft.com/en-us/dotnet/api/system._appdomain?view=netframework-4.8.1


```cpp
DWORD appDomainId = NULL;
	hr = pCorRuntimeHost->GetDefaultDomain(&spAppDomainThunk);
	if (FAILED(hr)) {
		wprintf(L"RuntimeClrHost::GetCurrentAppDomainId failed w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	hr = spAppDomainThunk->QueryInterface(IID_PPV_ARGS(&spDefaultAppDomain));
	if (FAILED(hr)) {
		wprintf(L"Failed to get default AppDomain w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}
```


Com a interface do AppDomain podemos de fato carrega-lo em memória. 

```spDefaultAppDomain->Load_3``` pega um array com os ```byte-code``` do custom ps runner e carrega em memória e também pega a ```Type``` interface do assembly carregado para usar depois.

- https://learn.microsoft.com/en-us/dotnet/api/system._appdomain.gettype?view=netframework-4.8.1#system-appdomain-gettype


```cpp
	// Load the .NET assembly.
	// Load our C# byte code into the current appdomain from memory (embeded byte code - PowerShellRunner DLL)
	SAFEARRAYBOUND bounds[1];
	bounds[0].cElements = PowerShellRunner_dll_len;
	bounds[0].lLbound = 0;

	// Create a safe array to store the array of BYTES from our unsigned CHAR elements
	SAFEARRAY* arr = SafeArrayCreate(VT_UI1, 1, bounds);
	SafeArrayLock(arr);
	memcpy(arr->pvData, PowerShellRunner_dll, PowerShellRunner_dll_len);
	SafeArrayUnlock(arr);

	hr = spDefaultAppDomain->Load_3(arr, &spAssembly);

	if (FAILED(hr)) {
		wprintf(L"Failed to load the assembly w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}

	// Get the Type of PowerShellRunner.
	hr = spAssembly->GetType_2(bstrClassName, &spType);
	if (FAILED(hr)) {
		wprintf(L"Failed to get the Type interface w/hr 0x%08lx\n", hr);
		goto Cleanup;
	}
```



Por ultimo, a função ```InvokeMethod``` que não faz parte da main é tipo um wrapper para o metodo ```InvokeMember_3``` da interface ```Type``` que chama ```InvokePS``` do assembly psrunner que executa de fato os comandos powershell. 


- https://learn.microsoft.com/en-us/dotnet/api/system.type.invokemember?view=netframework-4.8.1#system-type-invokemember(system-string-system-reflection-bindingflags-system-reflection-binder-system-object-system-object()-system-reflection-parametermodifier()-system-globalization-cultureinfo-system-string())
- https://learn.microsoft.com/en-us/dotnet/api/system.type?view=netframework-4.8.1


```cpp
	// Insert PowerShell Command here
	wchar_t* argument = ...

	if (argc < 2) {
		printf("No args found. Running code from hardcoded 'argument'\n");
		InvokeMethod(spType, L"InvokePS", argv[1]);
	} {
		InvokeMethod(spType, L"InvokePS", argv[1]);
	}
```


```cpp
void InvokeMethod(_TypePtr spType, wchar_t* method, wchar_t* command)
{
	...

	// Invoke the method from the Type interface.
	hr = spType->InvokeMember_3(
		bstrStaticMethodName, 
		static_cast<BindingFlags>(BindingFlags_InvokeMethod | BindingFlags_Static | BindingFlags_Public), 
		NULL, 
		vtEmpty, 
		psaStaticMethodArgs, 
	
    &vtPSInvokeReturnVal);

    ...
```


### Obs

Tive alguns problemas na primeira vez que abri o projeto no visual studio por estar parado a dez anos e sem atualização. 

- 1 - ```not found mscorlib.tlh```
- Você precisa build o projeto pelo menos uma vez. Ele irá gerar o arquivo mscorlib.tlh 

- 2 - Runtime versão 2.0.x não funciona, fixar versão 4.0.x

- 3 - Depois do primeiro build refazer o header file com a dll em byte-code. ```└─$ xxd -i PowerShellRunner.dll > PowerShellRunnerDll.h```.


## Build e Usage

Após um overview basico sobre o código, vamos para a parte pratica vendo como ele se comporta.


#### PowerView com powershell.exe

- cli + process


![pswps2](/img/pswps2.png)


![pswps](/img/pswps.png)



#### PowerView com UnmanagedPowerShell.exe


- cli + unmanagedpowershell.exe


![pswunmng2](/img/pswunmng2.png)


![pswunmng](/img/pswunmng.png)


#### full execution in memory com Donut + Sliver

Esse projeto achei interessante porque o cara adicionou PowerView e PowerUp e ainda deu a ideia de rodar tudo em memória convertendo o .exe final em um .bin com donut. Na teoria parece bom mas só o defender consegue bloquear facilmente então precisa de algumas modificações para ser mais stealth.

- [https://github.com/mmnoureldin/UnmanagedPowerShell](https://github.com/mmnoureldin/UnmanagedPowerShell)


### Detection - WinDefender

- O Windows Defender detecta o executavel final sem nenhuma modificação pra obfsucação.


![wdef](/img/wdef.png)



### Detection - LitterBox

- [https://github.com/BlackSnufkin/LitterBox](https://github.com/BlackSnufkin/LitterBox)

- LitterBox é um sandbox self-hosted que pussui analise estatica e dinâmica de varios tipos de samples. Na analise estatica foi pego com: uma regra yara, windefender, chamada GetProcAddress e LoadLibrary. Na analise dinâmica todos os scan pegaram: memória com RWX, carregamento de dll e algumas outras coisas que parecem mais falsos positivos mas mesmo assim triggaram.



![litterbox1](/img/litterbox1.png)


![litterbox2](/img/litterbox2.png)



# Conclusão

Essa foi uma pequena demonstração de como a tecnica funciona e como podemos usa-la, dependendo da criatividade do operador é possivel executar chains mias complexas que incluem essa poc e bypassar algumas coisas ...