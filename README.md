# Basic-Analyzer

🎯 **Amacı**: Bir alan adı (domain) üzerinden DNS kayıtlarını ve IP adreslerini analiz etmek amacıyla geliştirilmiş, temiz kod prensipleri ile yazılmış Python tabanlı CLI aracı.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![Code Style](https://img.shields.io/badge/code%20style-black-black.svg)

## 🚀 Özellikler

### ✅ Mevcut Özellikler
- **DNS Kayıtları**: A, AAAA, CNAME, MX, NS, TXT kayıtlarını getirir
- **Reverse DNS**: IP adreslerinden hostname çözümleme
- **GeoIP Analizi**: IP adreslerinin coğrafi konum, ISP ve ASN bilgileri
- **WHOIS Sorgulaması**: Domain kayıt bilgileri ve sahiplik detayları
- **Subdomain Discovery**: Temel subdomain keşif algoritması
- **Renkli CLI Çıktısı**: Kullanıcı dostu terminal arayüzü
- **JSON Export**: Sonuçları JSON formatında dosyaya kaydetme
- **Type Hints**: Tam type annotation desteği
- **Error Handling**: Kapsamlı hata yönetimi

### 🔄 Planlanan Özellikler
- WHOIS sorgulaması
- Subdomain discovery
- Port tarama
- Blacklist kontrolü
- SSL/TLS sertifika analizi

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

### Sonuçları JSON'a kaydetme
```bash
python main.py --domain example.com --geoip --reverse --output analiz_sonucu.json
```

### Tüm Parametreler
- `--domain`: Analiz edilecek domain adı (zorunlu)
- `--geoip`: IP adreslerinin GeoIP analizini yapar
- `--reverse`: Reverse DNS sorgulaması yapar
- `--output, -o`: Sonuçları JSON dosyasına kaydeder

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
    [2] _k2n1y4vw3qtb4skdx9e7dxt97qrmmq9

========== IP ADRESLERİ ANALİZİ ==========
[🔍] IP Adresi: 93.184.216.34
[+] Reverse DNS: 93.184.216.34
[+] Konum: Norwell, Massachusetts, United States
[+] ISP: Edgecast
[+] Organizasyon: EDGECAST-NETBLK-03
[+] AS: AS15133 Edgecast Inc.
[+] Koordinatlar: 42.1596, -70.8217
```

## 🛠️ Teknik Detaylar

- **Python**: 3.8+
- **Architecture**: Object-Oriented Design (OOP)
- **DNS**: `dnspython` kütüphanesi
- **GeoIP**: ip-api.com servisini kullanır
- **Renkli Çıktı**: `colorama` kütüphanesi
- **CLI**: `argparse` ile komut satırı arayüzü
- **Type Safety**: Full type hints with mypy support
- **Error Handling**: Specific exception handling
- **Code Quality**: PEP 8 compliant, clean code principles

### 🏗️ Kod Yapısı
```
main.py
├── DNSAnalyzer (Class)      # Ana DNS analiz sınıfı
│   ├── DNS sorgu metodları
│   ├── GeoIP ve Reverse DNS
│   ├── WHOIS ve Subdomain discovery
│   └── Sonuç formatlaması
└── CLIManager (Class)       # CLI yönetim sınıfı
    ├── Argüman parsing
    ├── İş akışı kontrolü
    └── Çıktı yönetimi
```

## 🎯 Kullanım Senaryoları

| Kullanıcı | Senaryo |
|-----------|---------|
| **Pentester** | Hedef domain'in IP ve mail altyapısını öğrenmek |
| **OSINT Araştırmacısı** | Domain'in SPF ve TXT kayıtlarından ilişkilendirme |
| **Sistem Yöneticisi** | DNS yapılandırmasında sorun kontrolü |
| **BT Güvenliği** | Domain'in güvenlik yapılandırması analizi |

## 📝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/AmazingFeature`)
3. Commit yapın (`git commit -m 'Add some AmazingFeature'`)
4. Push yapın (`git push origin feature/AmazingFeature`)
5. Pull Request açın

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır.
