# Sudomy
[![License](https://img.shields.io/badge/license-MIT-red.svg)](https://opensource.org/licenses/MIT)  [![Version](https://img.shields.io/badge/Release-1.1.0-blue.svg?maxAge=259200)]()   [![Build](https://img.shields.io/badge/Supported_OS-Linux-yellow.svg)]() [![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/screetsec/sudomy/issues)
### Subdomain Enumeration & Analysis
![ff](https://user-images.githubusercontent.com/17976841/63212795-b8d57300-c133-11e9-882a-f604d67819cc.png)

Sudomy adalah alat bantu subdomain enumeration, dibuat menggunakan bash script, untuk menganalisa domain dan mengumpulkan subdomain secara cepat dan lengkap. 

## Fitur
##### Saat ini, Sudomy memiliki 9 fitur, yaitu:
-  Mudah, cepat, ringan dan powerfull. Bash script tersedia secara default di semua distro linux. Dengan memanfaatkan fitur multipengolahan (multiprocessing) yang dimiliki oleh bash script, maka semua prosesor akan terpakai secara optimal.
-  Pengujian enumerasi dns menggunakan metode aktif atau pasif
    - **Metode aktif**
        - Sudomy memanfaatkan tools Gobuster, karena Gobuster sangat cepat dalam melakukan serangan DNS Subdomain Bruteforce (wildcard support). Wordlist yang dipakai berasal dari SecList (Discover/DNS). Beberapa file wordlist pada SecList kemudian disatukan menjadi sebuah file dengan total wordlist mencapai 3 juta entri.

    - **Metode Pasif**
        - Dengan menyeleksi situs pihak ketiga yang digunakan, proses enumerasi dns dapat dilakukan secara efektif dan efisien,  hasil yang didapatkan lebih banyak tapi waktu yang dibutuhkan lebih sedikit. Sudomy dapat mengumpulkan data dari ke-16 situs pihak ketiga yang telah melalui proses seleksi sebagai berikut:
    
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
- Pengujian terhadap daftar subdomain yang ditemukan untuk memastikan http atau https server berfungsi dengan baik. Fitur ini menggunakan tools pihak ketiga yaitu, [httprobe](https://github.com/tomnomnom/httprobe "httprobe").
- Pengecekan subdomain berdasarkan Ping Sweep dan/atau mendapatkan HTTP status code 
- Mampu mendeteksi virtualhost (beberapa subdomain yang berbagi satu alamat IP). Dari daftar subdomain yang ditemukan, Sudomy akan menerjemahkannya menjadi alamat IP, mengurutkan serta menggolongkannya apabila beberapa subdomain ternyata resolve ke alamat IP yang sama. Fitur ini akan sangat bermanfaat dalam proses pentest/bug bounty berikutnya, misal dalam melakukan port scanning, satu alamat ip tidak akan discan berulang-ulang.
- Melakukan port scanning dari alamat IP subdomain/virtualhost yang telah ditemukan
- Melakukan pengujian serangan Subdomain TakeOver
- Merekam tangkapan layar (screenshot) dari daftar subdomain
- Output laporan dalam format HTML atau CSV

## Cara Kerja
Sudomy menggunakan library cURL untuk mendapatkan HTTP Response Body pada situs pihak ketiga serta melakukan regex (regular expression) untuk kemudian menyusun daftar subdomain. Proses ini dilakukan secara multipengolahan (multiprocessing) sehingga  subdomain yang ditemukan lebih cepat dan banyak
## Komparasi
Berikut ini adalah hasil pengujian enumerasi dns secara pasif, perbandingan sudomy dengan Sublist3r dan Subfinder. Domain yang digunakan dalam melakukan komparasi :  ***bugcrowd.com***. 

|  Sudomy | Subfinder   | Sublister |
| ------------  | ------------ | ------------ |
|<img align="left" width="420" height="363" src="https://user-images.githubusercontent.com/17976841/63593207-b9f81b80-c5dd-11e9-9f46-f0cc53e032d4.gif">| <img align="left" width="430" height="363" src="https://user-images.githubusercontent.com/17976841/63592469-d85d1780-c5db-11e9-9e45-421653b65bad.gif"> | <img align="left" width="430" height="363" src="https://user-images.githubusercontent.com/17976841/63592249-55d45800-c5db-11e9-8ad0-80a5b70411c1.gif">   |

Asciinema : 
- [Subfinder](https://asciinema.org/a/260323)
- [Sudomy](https://asciinema.org/a/260324)
- [Sublist3r](https://asciinema.org/a/260325)

## Instalasi
Sudomy saat ini diperluas dengan alat-alat berikut. Petunjuk tentang cara menginstal & menggunakan aplikasi ini ditautkan di bawah ini.

|  Tools | License  | Info |
| ------------  | ------------ | ------------ | 
|  [Gobuster](https://github.com/OJ/gobuster) |  Apache License 2.0 | Tidak Wajib
|  [httprobe](https://github.com/tomnomnom/httprobe/) | Tom Hudson - | Wajib
|  [nmap](https://github.com/nmap/nmap) | GNU General Public License v2.0 | Tidak Wajib

### Dependencies
```
$ pip install -r requirements.txt
```
*Sudomy* membutuhkan [jq](https://stedolan.github.io/jq/download/) untuk menjalankanya. Untuk informasi lebih lanjut tentang cara mendownload dan instalasi [disini](https://stedolan.github.io/jq/download/)

```bash
# Linux 
apt-get install jq nmap

# Mac
brew install jq nmap
```

***Jika Anda memiliki lingkungan Go siap install dengan:***
```bash
export GOPATH=$HOME/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
go get -u github.com/tomnomnom/httprobe
go get -u github.com/OJ/gobuster
```

**Download Sudomy dari Github**
```bash
# Clone this repository
git clone --recursive https://github.com/screetsec/Sudomy.git

# Go into the repository
sudomy --help
```
### Pasca Instalasi
API Key diperlukan untuk melakukan query pada situs pihak ketiga seperti ```Shodan, Censys, SecurityTrails, Virustotal,``` dan ```BinaryEdge```. 
- Pengaturan API key dapat dilakukan melalui file sudomy.api
```bash
# Shodan
# URL :  http://developer.shodan.io
# Example :
#      - SHODAN_API="VGhpc1M0bXBsZWwKVGhmcGxlbAo"

SHODAN_API=""

# Censys
# URL : https://search.censys.io/register

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

## Petunjuk Pemakaian

```text
 ___         _ _  _           
/ __|_  _ __| (_)(_)_ __ _  _ 
\__ \ || / _  / __ \  ' \ || |
|___/\_,_\__,_\____/_|_|_\_, |
                          |__/ v{1.1.0#dev} by @screetsec 
Sud⍥my - Fast Subdmain Enumeration and Analyzer      
	 http://github.com/screetsec/sudomy

Usage: sud⍥my.sh [-h [--help]] [-s[--source]][-d[--domain=]] 

Example: sud⍥my.sh -d example.com   
         sud⍥my.sh -s Shodan,VirusTotal -d example.com
         sud⍥my.sh -pS -rS -sC -nT -sS -d example.com 

Optional Arguments:
  -a,  --all		 Running all Enumeration, no nmap & gobuster 
  -b,  --bruteforce	 Bruteforce Subdomain Using Gobuster (Wordlist: ALL Top SecList DNS) 
  -d,  --domain		 domain of the website to scan
  -h,  --help		 show this help message
  -o,  --html		 Make report output into HTML 
  -s,  --source		 Use source for Enumerate Subdomain
  -tO, --takeover	 Subdomain TakeOver Vulnerabilty Scanner
  -pS, --ping-sweep	 Check live host using methode Ping Sweep
  -rS, --resolver	 Convert domain lists to resolved IP lists without duplicates
  -sC, --status-code     Get status codes, response from domain list
  -nT, --nmap-top	 Port scanning with top-ports using nmap from domain list
  -sS, --screenshot	 Screenshots a list of website
  -nP, --no-passive	 Do not perform passive subdomain enumeration 
       --no-probe	 Do not perform httprobe 

```
Menggunakan seluruh situs pihak ketiga, kemudian melakukan pengujian apakah http/https server berfungsi dengan baik:
```
$ sudomy -d hackerone.com
```
Menggunakan salah satu situs pihak ketiga atau lebih: 
```
$ sudomy -s shodan,dnsdumpster,webarchive -d hackerone.com
```
Menggunakan satu atau lebih Plugin: 
```
$ sudomy -pS -sC -sS -d hackerone.com
```
Menggunakan seluruh Plugin , seperti pengecekan status host, status code, subdomain takeover, screenshots
```
$ sudomy --all -d hackerone.com
```

Membuat output laporan dalam format html
```
$ sudomy --all -d hackerone.com --html
```

Contoh output laporan HTML

| Dashboard	| Reports	|
| ------------  | ------------ | 
|![Index](https://user-images.githubusercontent.com/17976841/63597336-6ab6e880-c5e7-11e9-819e-91634e347b0c.PNG)|![f](https://user-images.githubusercontent.com/17976841/63597476-bbc6dc80-c5e7-11e9-8985-6a73348a2e02.PNG)|



## Gambaran Tools
- Youtube Videos : Click [here](http://www.youtube.com/watch?v=DpXIBUtasn0)


## Terjemahan
- Indonesia
- English


## Perubahan
Semua perubahan penting akan didokumentasikan [disini](https://github.com/Screetsec/sudomy/blob/master/CHANGELOG.md).


## Credits & Thanks
- [Tom Hudson](https://github.com/tomnomnom/) - Tomonomnom 
- [OJ Reeves](https://github.com/OJ/) - Gobuster
- [Thomas D Maaaaz](https://github.com/maaaaz) - Webscreenshot
- [Daniel Miessler](https://github.com/danielmiessler/) - SecList
- [EdOverflow](https://github.com/EdOverflow/) - can-i-take-over-xyz
- [NgeSEC](https://ngesec.id/) Community
- [Gauli(dot)Net](https://gauli.net/)
- [Bugcrowd](https://www.bugcrowd.com/) & [Hackerone](https://www.hackerone.com/)

