---
layout: post
title: cpl weaponization
date: 2026-06-02
description: cpl malware
categories: windows phishing redteam malware
tags: windows phishing redteam malware
---

* content
{:toc}







# CPL weaponization

CPL é um arquivo executavel/PE que são usados pelo Windows Control Panel (ou só Control Panel), cada ferramenta disponivel no control panel é um arquivo ```.cpl```.

Esses aquivos são basicamente DLLs que exportam a função ```CPLApplet``` funcionando como se fosse a "main" do CPL, da mesma forma que nos serviços precisam de funções especificas para iniciar a execução. A ideia é criar uma dll e depois renomear para ```.cpl```. Depois de criado a dll e renomeado, o arquivo cpl pode ser executado com ```double-click``` ou pela cli com o binario ```control.exe```.

- [https://attack.mitre.org/techniques/T1218/002/](https://attack.mitre.org/techniques/T1218/002/)

- [https://learn.microsoft.com/en-us/windows/win32/shell/using-cplapplet?redirectedfrom=MSDN](https://learn.microsoft.com/en-us/windows/win32/shell/using-cplapplet?redirectedfrom=MSDN)

Aqui um exemplo de código simples:

```cpp
// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <Windows.h>

//Cplapplet
extern "C" __declspec(dllexport) LONG Cplapplet(
	HWND hwndCpl,
	UINT msg,
	LPARAM lParam1,
	LPARAM lParam2
)
{
	MessageBoxA(NULL, "Hey there, I am now your control panel item you know.", "Control Panel", 0);
	return 1;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
		Cplapplet(NULL, NULL, NULL, NULL);
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

Então, ja que o .cpl é uma dll e pode ser executado facilmente (e de forma maliciosa), eles são usados na maioria das vezes como delivery de malware/dropper via phishing fazendo com que o alvo execute e dê inicio a infecção.

Pensando nisso existem varias formas de conseguir code-execution a partir dessa tecnica. Em alguns reports podemos ver o .cpl ser entregue incorporado a um RTF/Word, ou em um zip com arquivos nomeados como Fatura.cpl. Também vemos sendo usado em multi-stage malware e em persistencia.


- [https://web.archive.org/web/20170830201313/https://www.trendmicro.de/cloud-content/us/pdfs/security-intelligence/white-papers/wp-cpl-malware.pdf](https://web.archive.org/web/20170830201313/https://www.trendmicro.de/cloud-content/us/pdfs/security-intelligence/white-papers/wp-cpl-malware.pdf)

- [https://web.archive.org/web/20141213133208/https://blog.trendmicro.com/trendlabs-security-intelligence/control-panel-files-used-as-malicious-attachments/](https://web.archive.org/web/20141213133208/https://blog.trendmicro.com/trendlabs-security-intelligence/control-panel-files-used-as-malicious-attachments/)

- [https://unit42.paloaltonetworks.com/unit42-new-malware-with-ties-to-sunorcal-discovered/](https://unit42.paloaltonetworks.com/unit42-new-malware-with-ties-to-sunorcal-discovered/)

- [https://web-assets.esetstatic.com/wls/2020/06/ESET_InvisiMole.pdf](https://web-assets.esetstatic.com/wls/2020/06/ESET_InvisiMole.pdf)

- [https://somosagility.com.br/ataques-avancados-contra-cpl-control-panel-applets/](https://somosagility.com.br/ataques-avancados-contra-cpl-control-panel-applets/)


Mesmo com alguns exemplos claros "in the wild" essa tecnica ainda é pouco utilizada, talvez por ser facil de detectar e barrar, ou as pessoas não estão de olho nisso por não ser tão adotado pelos threat actors. De qualquer forma achei interessante pela flexibilidade de poder usar qualquer coisa que uma dll possa executar.


# POC

Para essa demonstração pensei em fazer um .cpl que seja um dropper/loader que executa um shellcode na memoria de outro processo. O código final que usei foi baseado nos 3 repositórios abaixo. A ideia era algo que daria bypass pelo menos no defender para os testes serem mais realistas, então decidi basear totalmente na poc HellsGate mas com algumas modificações.

Como c2 usei o Havoc, ja que os payloads do metasploit seriam pegos muito facil e os payloads do sliver são muito grandes.

- [https://github.com/am0nsec/HellsGate](https://github.com/am0nsec/HellsGate)
- [https://github.com/CognisysGroup/HadesLdr](https://github.com/CognisysGroup/HadesLdr)
- [https://github.com/raulm0429/HalosGate-Cpl-C-](https://github.com/raulm0429/HalosGate-Cpl-C-)

- Full code [https://github.com/geleiaa/HdsCplLdr](https://github.com/geleiaa/HdsCplLdr)


## Project build + usage

Abra o projeto no Visual Studio, faça as configs necessarias de setar ip, porta, fazer xor nas strings, etc. e depois build. Os scripts para xor e api hashing estão no repositório [https://github.com/CognisysGroup/HadesLdr](https://github.com/CognisysGroup/HadesLdr) caso queria modificar algo pode se basear la. O código que usei só tem o minimo pra ser funcional nada a mais.

Depois de compilado vá ate o diretório do projeto e renomeie a .dll para .cpl e para executar é double-click.


![renamedll](/img/renamedll.png)


Quando executado inicia um processo com o binario ```control.exe``` que inicia ```rundll32.exe``` para executar o cpl [https://medium.com/@boutnaru/the-windows-process-journey-control-exe-windows-control-panel-e952c95e2647](https://medium.com/@boutnaru/the-windows-process-journey-control-exe-windows-control-panel-e952c95e2647).


![control1](/img/control1.png)


## c2 callback


![havoccb](/img/havoccb.png)



![havocrce](/img/havocrce.png)




## Detection

Na analise estatica do defender o arquivo passa sem problema, mas as funções exportadas que não foram ofuscadas são pegas na analise estatica mais aprimorada.


![detection3](/img/detection3.png)



Na analise dinamica/runtime o shellcode puro do havoc é pego e a analise de memoria do processo notepad, que foi usado para a injeção do shellcode, o havoc ainda pode ser detectado.


![detection1](/img/detection1.png)



![detection2](/img/detection2.png)



## Conclusão

Com alguma ofuscação a mais das funções exportadas e customização de shellcode a detecção se torna mais dificil talvez até para soluções de proteção melhores, mas no geral é um boa opção. 

Como dito antes, os .cpl podem ser bem versateis para contrução de implants para initial access, podendo ser parte de multi-stage facilmente, está limitado apenas pela criatividade do operador.