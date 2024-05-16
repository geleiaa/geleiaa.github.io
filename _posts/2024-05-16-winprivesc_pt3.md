---
layout: post
title: windows priv-esc pt3
date: 2024-05-16
description: serie de windows Priv-Esc
categories: windows bhatagem
---


## # Execution Flow Hijacking

> #### Unsecured File System

- Busca em todo o disk C:\ por arquivos com perms read/write no grupo Users e Authenticated Users 
- ``` accesschk.exe -accepteula -wus "Users" c:\*.* > output.txt ```
- ``` accesschk.exe -accepteula -wus "Authenticated Users" c:\*.* > auth-usr.txt ```
  - em um cenário real você faz download do arquivo para a attack machine e analisa "offiline"

- Basicamente, procurando por paths de executaveis com perms read/write, a ideia é usar a tecnica de Execution Flow Hijacking [https://attack.mitre.org/techniques/T1574/007/](https://attack.mitre.org/techniques/T1574/007/) para substituir um binario legitimo pelo implant. Fazendo com que o implant, quando executado, "chame" o binario legitimo depois de executar o payload em um processo diferente...

demo em breve???...

READ/REFS:
  - [https://helgeklein.com/blog/finding-executables-in-user-writeable-directories/](https://helgeklein.com/blog/finding-executables-in-user-writeable-directories/ )


> #### Explorando Env Vars paths (Path Interception by PATH Environment Variable)

- Vendo as env vars
- ``` reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" ``` ou ```set```


- Checando perm de write no env PATH
- ```icacls c:\rto\bin```

- Se houver um caminho controlável nesta lista colocado, você poderá fazer com que o sistema execute seus próprios binários em vez dos reais.
- ``` copy c:\implant\implant.exe c:\bin\notepad.exe ```

READ/REFS:
- [https://attack.mitre.org/techniques/T1574/007/](https://attack.mitre.org/techniques/T1574/007/)


> #### Explorando Services sem o binario no path

- Buscando por services sem binario
- ``` c:\autorunsc64.exe -a s | more ```

- Info do service
- ``` C:\> sc query <service-name> ``` - lista services
- ``` C:\> sc qc <service-name> ``` - info do service


- Substituindo o binario
- ``` copy c:implant\implant.exe c:\path-to-service-sem-bin ```

- restart no service:

- ``` sc stop <service-name>``` e ``` sc start <service-name> ```


> #### Explorando Task sem binario no path 

A ideia é a mesma do Service sem binario...

- Buscando por Tasks sem bin:
- ``` c:\autorunsc64.exe -a s | more ```


- Checando configs da Task:
- ``` schtasks /query /tn <task-name> /xml ```

Nas configs procure pelo ```<UserId>``` (CID) para verificar a qual user pertence a task. Olhe também as configs ```<LogonType>``` e ```<RunLevel>``` para mais info do user daquela task.
Por ultimo, verifique a config ```<Triggers>``` que diz como aquela task é iniciada e com isso voĉe saberá como inicia-la.


- Substituindo binario:
- ``` copy c:implant\implant.exe C:\path-to-service-sem-bin ```

- Checando username do UserId (CID)
- ``` wmic useraccount where sid='S-1-5-21-3461203602-4096304019-2269080069-1003' get name ```


READ/REFS:
- [https://amr-git-dot.github.io/offensive/Priv-esc/](https://amr-git-dot.github.io/offensive/Priv-esc/)
- [https://gitbook.brainyou.stream/basic-windows/tcm-win-privesc#insecure-folders-files](https://gitbook.brainyou.stream/basic-windows/tcm-win-privesc#insecure-folders-files)


> #### DLL Hijacking (for priv-esc)

O DLL Hijacking envolve a manipulação de um programa confiável para carregar uma DLL maliciosa. Existem varias táticas como DLL Spoofing, Injection e Side-Loading. É utilizado principalmente para execução de código, persistência e, menos comumente, priv-esc. 
E nesse caso aqui será para priv-esc...

- Encontre em programa com DLL's marcadas como NOT FOUND

- Ache uma DLL para hijack

- Depois procure pelas funções especificas que o programa tenta importar da DLL not found:
  - dump da import table
  - ```c:\ dumpbin imports c:\path_to_target_program```

- Sabendo as funções que um programa tenta importar você pode pesquisar pelo implementação dessa DLL e tentar hijack...

```
Sim, os requisitos são complicados de encontrar, pois por padrão é meio estranho encontrar um executável privilegiado sem uma dll e é ainda mais estranho ter permissões de gravação em uma pasta do caminho do sistema (você não pode por padrão). Mas, em ambientes mal configurados isso é possível.
```

READ/REFS:
- [https://akimbocore.com/article/privilege-escalation-dll-hijacking/](https://akimbocore.com/article/privilege-escalation-dll-hijacking/)
- [https://www.ired.team/offensive-security/privilege-escalation/t1038-dll-hijacking](https://www.ired.team/offensive-security/privilege-escalation/t1038-dll-hijacking)
- [https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking#escalating-privileges](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking#escalating-privileges)
- [https://steflan-security.com/windows-privilege-escalation-dll-hijacking/](https://steflan-security.com/windows-privilege-escalation-dll-hijacking/)



> #### UAC

- [https://book.hacktricks.xyz/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control](https://book.hacktricks.xyz/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control)
- [https://github.com/hfiref0x/UACME](https://github.com/hfiref0x/UACME)


...