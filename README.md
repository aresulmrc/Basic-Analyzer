# Basic-Analyzer

🎯 **Amacı**: Bir alan adı (domain) üzerinden DNS kayıtlarını ve IP adreslerini analiz etmek için geliştirilmiş Python CLI aracı.

## 🚀 Özellikler

- **DNS Kayıtları**: A, AAAA, CNAME, MX, NS, TXT kayıtlarını getirir
- **Reverse DNS**: IP adreslerinden hostname çözümleme
- **GeoIP Analizi**: IP adreslerinin coğrafi konum, ISP ve ASN bilgileri
- **WHOIS Sorgulaması**: Domain kayıt bilgileri ve sahiplik detayları
- **Subdomain Discovery**: Temel subdomain keşif algoritması
- **JSON Export**: Sonuçları JSON formatında dosyaya kaydetme
- **Renkli CLI Çıktısı**: Kullanıcı dostu terminal arayüzü

## 📦 Kurulum

```bash
# Repoyu klonlayın
git clone https://github.com/aresulmrc/Basic-Analyzer.git
cd Basic-Analyzer

# Virtual environment oluşturun
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate     # Windows

# Gerekli paketleri kurun
pip install -r requirements.txt
```

## 🔧 Kullanım

### Temel DNS Analizi

```bash
python main.py --domain example.com
```

### GeoIP ve Reverse DNS ile

```bash
python main.py --domain example.com --geoip --reverse
```

### WHOIS Sorgulaması

```bash
python main.py --domain example.com --whois
```

### Subdomain Keşfi

```bash
# Varsayılan wordlist ile
python main.py --domain example.com --subdomains

# Özel wordlist dosyası ile
python main.py --domain example.com --subdomains --wordlist my_wordlist.txt
```

### Tüm Analizler + JSON Export

```bash
python main.py --domain example.com --all --output sonuc.json
```

### Parametreler

- `--domain`: Analiz edilecek domain adı (zorunlu)
- `--geoip`: IP adreslerinin GeoIP analizini yapar
- `--reverse`: Reverse DNS sorgulaması yapar
- `--whois`: Domain için WHOIS sorgulaması yapar
- `--subdomains`: Subdomain keşfi yapar
- `--wordlist, -w`: Subdomain taraması için özel wordlist dosyası
- `--all`: Tüm analizleri yapar
- `--output, -o`: Sonuçları JSON dosyasına kaydeder
- `--verbose, -v`: Detaylı log çıktısı

## 📊 Örnek Çıktı

```
========== DNS ANALİZİ ==========
[+] Domain: example.com
[+] A Kayıtları (IPv4): 93.184.216.34
[+] AAAA Kayıtları (IPv6): 2606:2800:220:1:248:1893:25c8:1946
[+] CNAME Kayıtları: Yok
[+] MX Kayıtları: .
[+] NS Kayıtları: a.iana-servers.net., b.iana-servers.net.
[+] TXT Kayıtları: 2 adet
    [1] v=spf1 -all
    [2] wgyf8z8cgvm2qmxpnbnldrcltvk4xqfn

========== IP ADRESLERİ ANALİZİ ==========
[🔍] IP Adresi: 93.184.216.34
[+] Reverse DNS: 93.184.216.34
[+] Konum: Norwell, Massachusetts, United States
[+] ISP: Edgecast
[+] Organizasyon: EDGECAST-NETBLK-03
[+] AS: AS15133 Edgecast Inc.
```

## � Wordlist Kullanımı

Subdomain keşfi için özel wordlist dosyası kullanabilirsiniz:

### Varsayılan Wordlist
- Proje klasöründe `wordlist.txt` dosyası bulunur
- 400+ subdomain terimi içerir
- Türkçe ve İngilizce terimler

### Özel Wordlist
```bash
# Kendi wordlist dosyanızı kullanın
python main.py --domain example.com --subdomains --wordlist my_wordlist.txt
```

### Wordlist Formatı
- Her satırda bir subdomain terimi
- Boş satırlar otomatik olarak atlanır
- UTF-8 encoding kullanın

**Örnek wordlist.txt:**
```
www
mail
ftp
admin
api
test
dev
```

## �🛠️ Teknik Detaylar

- **Python**: 3.8+
- **DNS**: `dnspython` kütüphanesi
- **GeoIP**: ip-api.com servisini kullanır
- **WHOIS**: `python-whois` kütüphanesi
- **Renkli Çıktı**: `colorama` kütüphanesi

## 🎯 Kullanım Senaryoları

| Kullanıcı               | Senaryo                                         |
| ----------------------- | ----------------------------------------------- |
| **Pentester**           | Hedef domain'in IP ve mail altyapısını öğrenmek |
| **OSINT Araştırmacısı** | Domain'in DNS kayıtlarından bilgi toplama       |
| **Sistem Yöneticisi**   | DNS yapılandırması kontrolü                     |
| **BT Güvenliği**        | Domain güvenlik analizi                         |

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır.
