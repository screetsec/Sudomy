# Sudomy
[![License](https://img.shields.io/badge/license-MIT-red.svg)](https://github.com/Screetsec/Sudomy/blob/master/LICENSE.md)  [![Build Status](https://travis-ci.org/Screetsec/Sudomy.svg?branch=master)](https://travis-ci.org/Screetsec/Sudomy)  [![Version](https://img.shields.io/badge/Release-1.1.5-blue.svg?maxAge=259200)]()  [![Build](https://img.shields.io/badge/Supported_OS-Linux-yellow.svg)]()  [![Build](https://img.shields.io/badge/Supported_WSL-Windows-blue.svg)]() [![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/screetsec/sudomy/issues)  [![Youtube](https://img.shields.io/badge/Youtube-Demo-red.svg)](https://www.youtube.com/watch?v=DpXIBUtasn0)
### Análise e Enumeração de Subdomínios
![ff](https://user-images.githubusercontent.com/17976841/63212795-b8d57300-c133-11e9-882a-f604d67819cc.png)

***Sudomy*** é uma ferramenta de enumeração de sub-domínios criada com bash script para analizar e coletar dominios e subdominions de forma rápida e compreensiva.

## Features!
##### Até o momento, ***Sudomy*** possui essas 13 features:
-  Facil, leve, rápido e poderoso. Bash scripts estão disponiveis por padrão em quase todas as distribuições Linux. Usando a feature de multiprocessamento do bash script, usamos todos os processadores distribuindo a carga entre eles, otimizando o processo.
-  O processo de enumeração de subdomínios pode ser alcançado usando o método **ativo** ou **passivo**.
    - **Método Ativo**
        - *Sudomy* utiliza ferramentas Gobuster por conta de sua alta performance na execução de ataques força-bruta em subdomínios em DNS. A wordlist usada vem de uma combinação de listas do SecList que possui cerca de 3 milhões de entradas.

    - **Método Passivo**
        - **Selecionando bons sites de terceiros**, o processo de enumeração pode ser otimizado. Mais resultados podem ser obtidos em menos tempo. *Sudomy* pode coletar dados destes 20 sites de terceiros:

                https://dnsdumpster.com
                https://web.archive.org
                https://shodan.io
                https://virustotal.com
                https://crt.sh
                https://www.binaryedge.io
                https://securitytrails.com
                https://sslmate.com/certspotter
                https://censys.io
                https://threatminer.org
                http://dns.bufferover.run
                https://hackertarget.com
                https://www.entrust.com/ct-search/
                https://www.threatcrowd.org
                https://riddler.io
                https://findsubdomains.com
                https://rapiddns.io/
                https://otx.alienvault.com/
                https://index.commoncrawl.org/
                https://urlscan.io/
- Teste a lista de subdomínios coletados e examine-os para encontrar servidores http e https ativos. Essa feature usa uma extensão chamada [httprobe](https://github.com/tomnomnom/httprobe "httprobe").
- Teste de disponibilidade de subdomínio utiliza o Ping Sweep e/ou o código HTTP retornado.
- A capacidade de detectar virtualhost (muitos domínios utilizando somente um endereço de IP). Sudomy irá resolver os subdomínios coletados à endereços de IP, e classifica-los se muitos subdomínios se resolvem em somente um único endereço de IP. Essa feature é bastante útil para o próximo passo durante testes de penetração ou bug bounties. Por exemplo, durante port scanning, um único endereço de IP não vai ser escaniado repetidas vezes.
- Executa port scanning a partir dos subdmínios coletados ou endereços de IP dos virtualhosts.
- Testa ataques Subdomain takeover
- Tira screenshots dos subdomínios
- Identify technologies on websites
- Coleta dados/Busca portas abertas através de terceiros (Default::Shodan), mas atualmente usa apenas Shodan [Future::Censys, Zoomeye]. Mais eficiente e assertivo em coletar portas através da lista de IP.
- Coleta Juicy URL & Extrai parametros de URL.
- Define um caminho para o arquivo de saída. (Especifique o arquivo de saída quando acabar)
- Gera um report em formatos HTML & CSV.

## Como Sudomy funciona
*Sudomy* esta usando a biblioteca cURL para obter o body das respostas HTTP a partir dos sites terceiros para após isso executar expressões regulares e obter os subdomínios. Esse processo aproveita totalmente todos os processadores e assim mais subdomínios serão coletados em menos tempo.

## Publicação
- [Sudomy: Information Gathering Tools for Subdomain Enumeration and Analysis](https://iopscience.iop.org/article/10.1088/1757-899X/771/1/012019/meta) -  IOP Conference Series: Materials Science and Engineering, Volume 771, 2nd International Conference on Engineering and Applied Sciences (2nd InCEAS) 16 November 2019, Yogyakarta, Indonesia

## Guia do usuário
- Guia do usuário offline : [Sudomy - Subdomain Enumeration and Analysis User Guide v1.0](https://github.com/Screetsec/Sudomy/blob/master/doc/Sudomy%20-%20Subdomain%20Enumeration%20%26%20Analaysis%20User%20Guide%20v1.0.pdf)
- Guia do usuário online : [Subdomain Enumeration and Analysis User Guide](https://sudomy.screetsec.web.id/features)

## Comparação
Abaixo estão os resultados de enumerações passivas em DNS usando *Sublist3r, Subfinder*, e *Sudomy*. O domínio usado para comparação foi o ***bugcrowd.com***.

|  Sudomy | Subfinder   | Sublister |
| ------------  | ------------ | ------------ |
|<img align="left" width="420" height="363" src="https://user-images.githubusercontent.com/17976841/63593207-b9f81b80-c5dd-11e9-9f46-f0cc53e032d4.gif">| <img align="left" width="430" height="363" src="https://user-images.githubusercontent.com/17976841/63592469-d85d1780-c5db-11e9-9e45-421653b65bad.gif"> | <img align="left" width="430" height="363" src="https://user-images.githubusercontent.com/17976841/63592249-55d45800-c5db-11e9-8ad0-80a5b70411c1.gif">   |

Asciinema :
- [Subfinder](https://asciinema.org/a/260323)
- [Sudomy](https://asciinema.org/a/260324)
- [Sublist3r](https://asciinema.org/a/260325)

## Instalação
*Sudomy* esta atualmente utilizando as seguintes ferramentas. As instruções de como instala-las & usa-las estão linkadas abaixo.

|  Tools | License  | Info |
| ------------  | ------------ | ------------ |
|  [Gobuster](https://github.com/OJ/gobuster) |  Apache License 2.0 | Não obrigatório
|  [httprobe](https://github.com/tomnomnom/httprobe/) | Tom Hudson - | Obrigatório
|  [nmap](https://github.com/nmap/nmap) | GNU General Public License v2.0 | Não obrigatório

### Baixando Sudomy do GitHub
```bash
# Clone o repositório
git clone --recursive https://github.com/screetsec/Sudomy.git
```

### Dependências
```
$ pip install -r requirements.txt
```
*Sudomy* precisa [jq](https://stedolan.github.io/jq/download/) para roda e fazer parse. Informações sobre como baixar e instalar podem ser acessadas [aqui](https://stedolan.github.io/jq/download/)

```bash
# Linux
apt-get update
apt-get install jq nmap phantomjs golang npm
npm i -g wappalyzer

# Mac
brew cask install phantomjs 
brew install jq nmap go npm
npm i -g wappalyzer
```

***Se você já tiver o ambiente Go, então siga essas instruções:***

Adicione as seguintes linhas ao seu ~/.bashrc (Do seu usuário)
```
nano ~/.bashrc
export GOPATH=$HOME/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
source ~/.bashrc
```
Então instale as dependências
```
go get -u github.com/tomnomnom/httprobe 
go get -u github.com/OJ/gobuster
```

## Rodando dentro de um container Docker
```bash
# Dê pull na imagem a partir do DockerHub
docker pull screetsec/sudomy:v1.1.5-dev

# Rode a imagem. Você pode rodar a imagem de qualquer diretório, mas você deve copiar/baixar a configuração sudomy.api no seu diretório atual.
docker run -v "${PWD}/output:/usr/lib/sudomy/output" -v "${PWD}/sudomy.api:/usr/lib/sudomy/sudomy.api" -it --rm screetsec/sudomy:v1.1.5-dev [argument]

ou definir a variável API enquanto estiver executando.

docker run -v "${PWD}/output:/usr/lib/sudomy/output" -e "SHODAN_API=xxxx" -e "VIRUSTOTAL=xxxx" -it --rm screetsec/sudomy:v1.1.5-dev [argument]
```

### Pós-Instalação
A chave da API é necessária antes da busca em sites terceiros, como por exemplo ```Shodan, Censys, SecurityTrails, Virustotal,``` e ```BinaryEdge```.
- A chave da API pode ser setada no arquivo sudomy.api.
```bash
# Shodan
# URL :  http://developer.shodan.io
# Example :
#      - SHODAN_API="VGhpc1M0bXBsZWwKVGhmcGxlbAo"

SHODAN_API=""

# Censys
# URL : https://censys.io/register

CENSYS_API=""
CENSYS_SECRET=""

# Virustotal
# URL : https://www.virustotal.com/gui/
VIRUSTOTAL=""


# Binaryedge
# URL : https://app.binaryedge.io/login
BINARYEDGE=""


# SecurityTrails
# URL : https://securitytrails.com/
SECURITY_TRAILS=""
```

## Uso

```text
 ___         _ _  _
/ __|_  _ __| (_)(_)_ __ _  _
\__ \ || / _  / __ \  ' \ || |
|___/\_,_\__,_\____/_|_|_\_, |
                          |__/ v{1.1.5#dev} by @screetsec
Sud⍥my - Fast Subdmain Enumeration and Analyzer
	 http://github.com/screetsec/sudomy

Usage: sud⍥my.sh [-h [--help]] [-s[--source]][-d[--domain=]]

Example: sud⍥my.sh -d example.com
         sud⍥my.sh -s Shodan,VirusTotal -d example.com
         sud⍥my.sh -pS -rS -sC -nT -sS -d example.com

Optional Arguments:
  -a,  --all             Running all Enumeration, no nmap & gobuster 
  -b,  --bruteforce      Bruteforce Subdomain Using Gobuster (Wordlist: ALL Top SecList DNS) 
  -d,  --domain          domain of the website to scan
  -h,  --help            show this help message
  -o,  --outfile         specify an output file when completed 
  -s,  --source          Use source for Enumerate Subdomain
  -aI, --apps-identifier Identify technologies on websites from domain list
  -dP, --db-port         Collecting port from 3rd Party default=shodan
  -eP, --extract-params  Collecting URL Parameter from Engine
  -tO, --takeover        Subdomain TakeOver Vulnerabilty Scanner
  -pS, --ping-sweep      Check live host using methode Ping Sweep
  -rS, --resolver        Convert domain lists to resolved IP lists without duplicates
  -sC, --status-code     Get status codes, response from domain list
  -nT, --nmap-top        Port scanning with top-ports using nmap from domain list
  -sS, --screenshot      Screenshots a list of website
  -nP, --no-passive      Do not perform passive subdomain enumeration 
       --no-probe        Do not perform httprobe 
       --html            Make report output into HTML 

```
Para usar todas as 20 fontes de busca por servidores http or https:
```
$ sudomy -d hackerone.com
```
Para usar uma ou mais fontes:
```
$ sudomy -s shodan,dnsdumpster,webarchive -d hackerone.com
```
Para usar um ou mais plugins:
```
$ sudomy -pS -sC -sS -d hackerone.com
```
Para usar todos os plugins: testar status do host, http/https status code, subdomain takeover and screenshots. 

Nmap,Gobuster e wappalyzer não estão incluídos.
```
$ sudomy --all -d hackerone.com
```

Para criar um report em formato HTML
```
$ sudomy --all -d hackerone.com --html
```

Exemplo de report HTML:

| Dashboard	| Reports	|
| ------------  | ------------ |
|![Index](https://user-images.githubusercontent.com/17976841/63597336-6ab6e880-c5e7-11e9-819e-91634e347b0c.PNG)|![f](https://user-images.githubusercontent.com/17976841/63597476-bbc6dc80-c5e7-11e9-8985-6a73348a2e02.PNG)|



## Overview das Ferramentas
- Youtube Videos : Click [here](http://www.youtube.com/watch?v=DpXIBUtasn0)


## Traduções
- Indonesia
- English
- Portuguese - Brazil


## Changelog
Qualquer mudança importante neste projeto será documentada neste [arquivo](https://github.com/Screetsec/sudomy/blob/master/CHANGELOG.md).


## Créditos & Agradecimentos
- [Tom Hudson](https://github.com/tomnomnom/) - Tomonomnom
- [OJ Reeves](https://github.com/OJ/) - Gobuster
- [Thomas D Maaaaz](https://github.com/maaaaz) - Webscreenshot
- [christophetd](https://github.com/christophetd/censys-subdomain-finder) - Censys
- [Daniel Miessler](https://github.com/danielmiessler/) - SecList
- [EdOverflow](https://github.com/EdOverflow/) - can-i-take-over-xyz
- [jerukitumanis](https://github.com/myugan) - Docker Maintainer
- [NgeSEC](https://ngesec.id/) - Community
- [Zerobyte](http://zerobyte.id/) - Community
- [Gauli(dot)Net](https://gauli.net/)
- [Bugcrowd](https://www.bugcrowd.com/) & [Hackerone](https://www.hackerone.com/)
