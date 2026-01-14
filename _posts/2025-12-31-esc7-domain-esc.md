---
layout: post
title: ESC7 domain escalation
date: 2025-12-31
description: priv-esc windows redteam
categories: priv-esc windows redteam
tags: priv-esc windows redteam
---

* content
{:toc}






# ESC7 ADCS privilege escalation

Antes de tudo vamos para o contexto, o que é ADCS? o que é ESC7? e como escalar privilégio com isso?

O ```ADCS``` é a implementação do PKI (Public Key Infrastructure — a system to manage certificates/public key encryption) da Microsoft que fornece tudo, desde criptografia de sistemas de arquivos, assinaturas digitais até autenticação de usuário e muito mais. Basicamente ADCS + PKI fornecem os ceritifcados para usuários, machines e etc num AD para fins de assinaturas e pricipalmente autenticação.

Os ```Certificates``` seguem o padrão X.509 e normalmente tem alguns campos como:

- Subject - O "dono" do certificado
- Issuer - Quem emitiu o certificado (normalmente a Certification Authority aka CA)
- Signature - A assinatura que geralmente é feita pela private key da CA
- NotBefore and NotAfter - Que seria a validade do certificado

Nos certificados também temos os formatos de arquivo que são ```.pfx```, ```.p12```, ```.pem``` e ```.crt```. Os formatos .pfx e .p12 são praticamente a mesma coisa, eles contem as infos de um certificado junto com a private key associado à ele. Agora os formatos .pem e .crt contem apenas a public key, o .pem é um base64, ja o .crt pode ser base64 ou binario (DEM format).

Esses campos entre outros compoem um certificado mas comumente as informações são vinculadas com alguma identidade (o Subject), dessa forma pode ser usado para assinar/autenticar.

As ```CA```s (Certication Authority) são responsáveis pela emissão dos certificados usando sua própria public-private key, ou seja, a CA é self-signed. As CAs definem os ```root CA certificates``` que são são a base trust de um ADCS e podem ser usados para verificar outros certificados.

Dentro da CA existem os ```Certificate Templates``` que definem os modelos de certificado habilitados. Esses modelos são configurações que a CA usa ao criar um certificado e inclui itens como EKUs, enroll permissions, expiração do certificado e etc. O ADCS armazena os templates como objetos no AD e os atributos desses objetos definem as configs como os ```enrollment rights```. 

Os enrollment rights são as permissões de um template (basicamente ACEs/ACLs), permissões do tipo: quem pode solicitar o certificado? quem é o owner do certificado? e por ai vai. Essas permissões podem der baseadas em usuários, grupos ou basicamente qualquer filtro de objeto.

Outra parte importante das permissões dos certificados são os EKUs (Extended Key Usage). As EKUs são definidos por OIDs (Object Identifiers) que descrevem como um certificado pode ser usado, por exemplo, para autenticação no AD ou para assinaturas.


### Como um certificado é obtido?

Depois de uma pequena introdução vamos para: como é e o que acontece quando um certificado é emitido.

O processo para obter um certificado é chamado de ```"Enrollment"```. Durante o Enrollment um client primeiro solicita alguns objetos da CA que estão no ```Ènrollment Services``` container. Depois o client gera um par de keys (public-private) e manda a public key no "signing request" (CSR - Certificate Signing Request) junto com outras infos como o Subject e o nome do Template. 

Então o client assina o CSR com a private key e manda para a CA que verifica os "enrollment rights". A CA verifica se o client pode solicitar o determinado Template ("if can enroll"), se sim, gera o certificado copiando as configs do Template (como EKUs e outras permissões) e por fim assina o certificado usando sua private key e retorna o cert para o client.

Em maquinas Windows você pode solicitar cetificados usando a GUI (```certmngr.msc``` user certs, ```certml.msc``` computer certs). Também é possível pela CLI com o binario ```certreq.exe``` ou com o powershell usando ```Get-Certificate```.


![enrollment](/img/enrollment.png)


Existem varias outras informações relevantes sobre o ADCS no geral mas isso é só uma introdução ao assunto para daqui em diante conseguir se aprofundar em uma exploração especifica, o path ESC7.

- https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
- https://www.vaadata.com/blog/understanding-active-directory-certificate-services-ad-cs/
- https://www.tarlogic.com/blog/ad-cs-esc7-attack/


## ESC7 

O path ESC7 não está relacionado aos certificados em si, mas sim em permissões de um usuário sobre a CA. As permissões são ```ManageCA``` e ```ManageCertificates``` aka "CA Administrator" e "CA Officer" respectivamente. Em alguns cenários podemos ver essas duas juntas, porém, para essa poc inicialmente vamos ver um usuário com ManageCA apenas.

Usando o modulo PSPKI podemos buscar as infos fazendo um recon pra saber se temos essas permissões:

![findperms](/img/findperms.png)

imagem 1

Podemos ver que o user "gMSA_CA_prod$" tem a perm ManageCA mas não a ManageCertificates (imagem 1). Com certipy também temos o mesmo resultado, a perm ManageCertificates está restrita ao grupo DomainAdmins (imagem 2).


![certifyperms](/img/certifyperms.png)

imagem 2


Com a permissão ManageCA é possivel mudar configurações da CA, isso pode ser usado para editar a flag ```EDITF_ATTRIBUTESUBJECTALTNAME2``` do registry ```HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA-NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy``` no valor ```EditFlags```. Habilitando essa flag na CA você permite que qualquer certificado possa usar o atributo ```SAN (Subject Alternative Name)``` e isso possibilita emitir certificados em nome de outros usuários, abrindo o path para o ```ESC6```.

Ok, enumeramos as permissões do user sobre a CA, e agora? ...


### Setando EDITF_ATTRIBUTESUBJECTALTNAME2

Agora vamos ver como podemos fazer isso usando o modulo powershell PSPKI. Esse modulo é usado especificamente para ADCS. Aqui temos exemplos de como usar esse modulo e editar essa flag facilmente [paper specterops](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf), [exposing to ESC6](https://www.thehacker.recipes/ad/movement/adcs/access-controls#esc7-exposing-to-esc6)


```sh
Install-Module -Name PSPKI
Import-Module PSPKI

# Get the current value of EDITF_ATTRIBUTESUBJECTALTNAME2 and modify it with SetConfigEntry
$configReader = New-Object SysadminsLV.PKI.Dcom.Implementations.CertSrvRegManagerD "CA.domain.local"
$configReader.SetRootNode($true)
$configReader.GetConfigEntry("EditFlags", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")
$configReader.SetConfigEntry(1376590, "EditFlags", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")

# Check after setting the flag (EDITF_ATTRIBUTESUBJECTALTNAME2 should appear in the output)
certutil.exe -config "CA.domain.local\CA" -getreg "policy\EditFlags"
```

Como está comentado no código acima, primeiro o modulo PSPKI é importado, depois a classe ```CertSrvRegManagerD``` é instanciada dando acesso aos métodos ```GetConfigEntry``` e ```SetConfigEntry```. Em seguida pega os dados do registry em que está armazenado o valor EditFlags. Por ultimo seta as flags com o valor ```1376590```, esse valor é o decimal que corresponde ao ```0x15014E``` hexadecimal, quem vem de uma operação "OR bitwise" e cada flag corresponde a um valor como na imagem abaixo depois que as flags são setadas.

Obs: também é possivel editar esse valor usando ferramentas nativas de registry management, mas em alguns casos apenas usuários admins podem editar diretamente os registries.

![flagset](/img/flagset.png)


Rodando o Certify novamente vemos que agora a CA é vulneravel ao ESC6:


![vulnca](/img/vulnca.png)



#### Mas agora temos um problema. 

Tentando seguir o path ESC6 e requisitar um certificado em nome de outro usuário recebo um famoso "Access Denied" e "Insufficient Permissions", ou seja, existe alguma politica habilitada que está barrando a emissão (provavelmente alguma policy padrão de AD por se tratar de uma maquina de ctf). 


![failedtry1](/img/failedtry1.png)


![failedtry2](/img/failedtry2.png)



Usando o certutil para pegar infos mais especificas de cada template podemos ver que eles só podem ser usados estritamente por admins, então o usuário atual não tem permissões para requisitar certificados e é provavel que somente requisitar um certificado com SAN não será suficiente, precisamos de mais permissões.


![templperms](/img/templperms.png)


## ESC6 + ESC16

Isso pode ser a solução para o problema. Na wiki da ferramente ```certipy``` (uma alternativa em python para o Certify) podemos encontrar as seguintes informações sobre o path ESC6 [https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc6-ca-allows-san-specification-via-request-attributes](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc6-ca-allows-san-specification-via-request-attributes):

"In modern, patched Active Directory environments - specifically, those with CAs and DCs that have received the May 2022 security updates addressing Certifried/CVE-2022-26923 and later - ESC6 alone is generally not sufficient for privilege escalation if certificates include the ```szOID_NTDS_CA_SECURITY_EXT``` (SID security extension). This is because the ```KDC prioritizes the SID``` from this security extension for mapping the certificate to an account during Kerberos PKINIT authentication. If an attacker uses ESC6 to inject a UPN for Administrator and a SID for Administrator into the SAN of a certificate, but the certificate is legitimately issued for the attacker's own account (and thus the SID security extension contains the attacker's SID), the KDC will use the attacker's SID, preventing impersonation."

Resumindo, mesmo que eu conseguisse solicitar um certificado seguindo o path ESC6 com um SAN arbitrario e tentar autenticar com ele, o KDC não verifica o SAN e sim o SID da conta que solicitou o certificado. Sendo assim não acontece uma impersonation.

Na mesma wiki do certipy tem uma sugestão de path combinados, nesse caso o ESC6 + ESC16. Basicamente precisamos fazer mais alterações nas configs do ADCS para abrir o path para o ESC16.

Blz então como isso funciona? ...


### ESC16 

O escalation ESC16 acontece quando na CA está desabilitado a ```security extension``` (ou SID security extension aka ```szOID_NTDS_CA_SECURITY_EXT``` ```OID: 1.3.6.1.4.1.311.25.2```) nos certificados emitidos. 

Isso funciona da seguinte forma: Se nós adicionarmos o ```OID: 1.3.6.1.4.1.311.25.2``` na policy ```DisableExtensionList``` do ADCS, quando um certificado for emitido, na hora da autenticação, o KDC vai verificar o SID associado à aquele certificado para autorizar ou não o uso dele, mas com essa proteção desabilitada o KDC não irá fazer esse "filtro" por SID, autorizando qualquer um a se autenticar com um certificado em nome de outro usuário.

Outra parte importante citada em varios lugares sobre o ESC16 é em relação ao ```StrongCertificateBindingEnforcement``` do KDC. Esse StrongCertificateBindingEnforcement aka "Full Enforcement" é basicamente um proteção que o AD tem contra impersonation em certificados. Ele funciona fazendo ```certificate mapping``` analisando o vinculo entre o certificado o e usuário na hora da autenticação. 

O StrongCertificateBindingEnforcement está em um registry key e tem 3 modos de atuação, ```0 = desabilitado, 1 = compatibility mode (proteção fraca) e 2 = Full Enforcement```. Obviamente para que o path ESC6 + ESC16 funcione bem precisamos que essa proteção esteja desabilitada...


### StrongCertificateBindingEnforcement e DisableExtensionList

Agora que já sabemos o que precisamos vamos verificar a situação do ADCS alvo e fazer as alterações.

Primeiro vamos verificar o StrongCertificateBindingEnforcement. Ele se encontra na registry key ```HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc\``` e podemos consulta-la facilmente. Para nossa sorte ele está desabilitado:


![StrongCertificateBindingEnforcement](/img/StrongCertificateBindingEnforcement.png)


Depois vamos para a ```DisableExtensionList``` e desabilitar a security extension:

Podemos ver que não ha nenhuma extenção desabilitada porque os valores estão zerados.


![DisableExtensionList](/img/DisableExtensionList.png)


Para adicionar alguma "extension exclusion" podemos fazer de varias formas mas aqui vou usar o mesmo código usado antes para habilitar o path ESC6 para que possamos colocar tudo em um único script a editar as configs necessarias:

```sh

$configReader.GetConfigEntry("DisableExtensionList", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")
$configReader.SetConfigEntry("1.3.6.1.4.1.311.25.2", "DisableExtensionList", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")


certutil -getreg policy\DisableExtensionList
```

O trecho acima é faz o mesmo do código anterior, a única diferença é qual policy, valor e registry vai ser alterado.

Depois se setar a security extension podemos consultar o registry pra ver se está tudo no lugar:


![secextdisable](/img/secextdisable.png)


Agora vem um parte importante mencionado nesses dois resources [ad-cs-esc16-misconfiguration-and-exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6) [ESC7 - Exposing to ESC6](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6) é que precisamos fazer o restartar o service ```CertSvc``` para que as alterações sejam aplicadas. Então se adicionarmos a seguinte comando no final do script tudo se resolve:

```sh
Restart-Service certsvc -Force
```  

O script final fica desse jeito:

```sh
import-module PSPKI

# Enabling EDITF_ATTRIBUTESUBJECTALTNAME2 flag

$configReader = New-Object SysadminsLV.PKI.Dcom.Implementations.CertSrvRegManagerD "dc01.fries.htb"
$configReader.SetRootNode($true)


$configReader.GetConfigEntry("EditFlags", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")
$configReader.SetConfigEntry(1376590, "EditFlags", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")

Start-Sleep -Seconds 2

# Check if is disabled

certutil.exe -config "dc01.fries.htb\fries-DC01-CA" -getreg "policy\EditFlags"

Start-Sleep -Seconds 2

# Enable DisableExtensionList

$configReader.GetConfigEntry("DisableExtensionList", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")
$configReader.SetConfigEntry("1.3.6.1.4.1.311.25.2", "DisableExtensionList", "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")

Start-Sleep -Seconds 2

# Check disable

certutil -getreg policy\DisableExtensionList

Start-Sleep -Seconds 2

# Restarting certsvc

Restart-Service certsvc -Force
```

Para verificar se tudo ocorreu como esperado podemos usar a ferramente certipy para achar algo vulneravel no alvo.


![finalvulnfind](/img/finalvulnfind.png)



## Solicitando certificado como Administrator

Depois de todas as alterações estamos prontos para solicitar o certificado fazendo a impersonation. 


![reqcert](/img/reqcert.png)


Obs: você pode ter notado que o usuário usado para explorar a vuln é difirente do usuário que tem a permissão sobre a CA. Isso é porque o usuário "CA-admin" não é um usuário comum, ele é usado somente como "service manager" e não pode Enroll em nenhum certificado, então para fazer a impersoantion precisaria de um usuário comum que fazer parte do grupo "Users" ou "Domain Users" e que possa Enroll em certificados. Esse também é o motivo de ter usado a certipy externamente, porque nessa maquina só tem acesso ao shell do usuário gMSA_CA_prod$, então a solução geral foi usar outro, o svc_infra.



## Conclusão

Essa foi uma pequena demonstração de como explorar o priv-esc ESC7 de uma forma "simples" indo direto ao ponto, mostrando o que fazer caso você se depare com essas permissões em um usuário, como editar as configs da CA para abrir o path ESC e causar mais impacto. Já que o foco não era explicar em detalhes como o ADCS funciona, tentei dar um overview e algumas referências sobre o assunto para que o leitor possa se aprofundar caso deseje.

