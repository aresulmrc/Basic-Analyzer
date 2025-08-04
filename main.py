#!/usr/bin/env python3
"""
Basic-Analyzer - DNS ve IP Analiz Aracı
GitHub: https://github.com/aresulmrc/Basic-Analyzer

Bu araç domain adları için kapsamlı DNS analizi yapar.

Özellikler:
- DNS kayıtları (A, AAAA, CNAME, MX, NS, TXT)
- GeoIP analizi
- Reverse DNS
- WHOIS bilgileri
- Subdomain keşfi
- JSON export
- Logging

Author: aresulmrc
License: MIT
Version: 1.0.0
"""

import argparse
import json
import logging
import socket
from datetime import datetime
from typing import Dict, List, Optional, Union, Any

import dns.resolver
import requests
import whois
from colorama import Fore, Style, init

# Sabitler
API_TIMEOUT = 5
DEFAULT_WORDLIST_SIZE = 30
JSON_INDENT = 2
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# GeoIP API endpoint
GEOIP_API_URL = "http://ip-api.com/json/{ip}"

# Renkli terminal çıktısı için başlat
init(autoreset=True)

# Logging yapılandırması
logging.basicConfig(
    level=logging.WARNING,
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler('dns_analyzer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class DNSAnalyzerException(Exception):
    """DNS Analyzer'a özgü exception sınıfı"""
    pass


class DNSAnalyzer:
    """DNS analiz işlemlerini gerçekleştiren ana sınıf"""
    
    def __init__(self, verbose: bool = False):
        self.results: Dict[str, Any] = {}
        self.verbose = verbose
        if verbose:
            logger.setLevel(logging.INFO)
    
    def print_header(self, title: str) -> None:
        """Başlık yazdırır"""
        print(f"\n{Fore.CYAN}{'='*10} {title} {'='*10}{Style.RESET_ALL}")
    
    def _query_dns_record(self, domain: str, record_type: str) -> List[str]:
        """DNS sorgusu yapar ve sonuçları döner"""
        try:
            answers = dns.resolver.resolve(domain, record_type)
            
            if record_type in ["A", "AAAA"]:
                return [rdata.address for rdata in answers]
            elif record_type == "TXT":
                return [rdata.strings[0].decode() for rdata in answers if rdata.strings]
            else:
                return [str(rdata.target if hasattr(rdata, 'target') else rdata.exchange) for rdata in answers]
                
        except dns.resolver.NXDOMAIN:
            logger.info(f"Domain {domain} bulunamadı ({record_type})")
            return []
        except dns.resolver.NoAnswer:
            logger.info(f"Domain {domain} için {record_type} kaydı yok")
            return []
        except dns.resolver.Timeout:
            logger.warning(f"DNS sorgusu zaman aşımı: {domain} ({record_type})")
            return []
        except Exception as e:
            logger.error(f"DNS sorgu hatası {domain} ({record_type}): {e}")
            return []
    
    def get_a_records(self, domain: str) -> List[str]:
        """A kayıtlarını getirir"""
        return self._query_dns_record(domain, "A")
    
    def get_aaaa_records(self, domain: str) -> List[str]:
        """AAAA kayıtlarını getirir"""
        return self._query_dns_record(domain, "AAAA")
    
    def get_cname_records(self, domain: str) -> List[str]:
        """CNAME kayıtlarını getirir"""
        return self._query_dns_record(domain, "CNAME")
    
    def get_mx_records(self, domain: str) -> List[str]:
        """MX kayıtlarını getirir"""
        return self._query_dns_record(domain, "MX")
    
    def get_ns_records(self, domain: str) -> List[str]:
        """NS kayıtlarını getirir"""
        return self._query_dns_record(domain, "NS")
    
    def get_txt_records(self, domain: str) -> List[str]:
        """TXT kayıtlarını getirir"""
        return self._query_dns_record(domain, "TXT")
    
    def get_reverse_dns(self, ip: str) -> Optional[str]:
        """IP adresinden hostname çözümler"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            logger.info(f"Reverse DNS başarılı: {ip} -> {hostname}")
            return hostname
        except socket.herror as e:
            logger.info(f"Reverse DNS bulunamadı: {ip} - {e}")
            return None
        except socket.gaierror as e:
            logger.warning(f"Reverse DNS ağ hatası: {ip} - {e}")
            return None
        except OSError as e:
            logger.error(f"Reverse DNS sistem hatası: {ip} - {e}")
            return None
    
    def get_geoip_info(self, ip: str) -> Optional[Dict[str, Union[str, float]]]:
        """IP adresinin coğrafi konum bilgilerini alır"""
        try:
            response = requests.get(
                GEOIP_API_URL.format(ip=ip), 
                timeout=API_TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    logger.info(f"GeoIP başarılı: {ip}")
                    return {
                        'country': data.get('country', 'Bilinmiyor'),
                        'region': data.get('regionName', 'Bilinmiyor'),
                        'city': data.get('city', 'Bilinmiyor'),
                        'isp': data.get('isp', 'Bilinmiyor'),
                        'org': data.get('org', 'Bilinmiyor'),
                        'as': data.get('as', 'Bilinmiyor'),
                        'lat': data.get('lat', 0.0),
                        'lon': data.get('lon', 0.0)
                    }
                else:
                    logger.warning(f"GeoIP API hatası: {data.get('message', 'Bilinmeyen hata')}")
            else:
                logger.warning(f"GeoIP HTTP hatası: {response.status_code}")
                
        except requests.Timeout:
            logger.warning(f"GeoIP zaman aşımı: {ip}")
        except requests.RequestException as e:
            logger.error(f"GeoIP bağlantı hatası: {ip} - {e}")
        except json.JSONDecodeError as e:
            logger.error(f"GeoIP JSON parse hatası: {ip} - {e}")
        
        return None
    
    def get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Domain için WHOIS bilgilerini getirir"""
        try:
            w = whois.whois(domain)
            
            def _safe_get_date(date_field) -> str:
                if isinstance(date_field, list) and date_field:
                    return str(date_field[0])
                elif date_field:
                    return str(date_field)
                return 'Bilinmiyor'
            
            logger.info(f"WHOIS başarılı: {domain}")
            return {
                'registrar': w.registrar or 'Bilinmiyor',
                'creation_date': _safe_get_date(w.creation_date),
                'expiration_date': _safe_get_date(w.expiration_date),
                'updated_date': _safe_get_date(w.updated_date),
                'name_servers': w.name_servers or [],
                'status': w.status or [],
                'emails': w.emails or [],
                'org': w.org or 'Bilinmiyor',
                'country': w.country or 'Bilinmiyor'
            }
        except Exception as e:
            logger.error(f"WHOIS hatası {domain}: {e}")
            return {'error': str(e)}
    
    def discover_subdomains(self, domain: str, wordlist: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Temel subdomain keşfi yapar"""
        if not wordlist:
            wordlist = [
                'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'dev', 'test', 'staging',
                'cdn', 'assets', 'img', 'images', 'static', 'docs', 'help', 'support',
                'shop', 'store', 'app', 'mobile', 'secure', 'vpn', 'remote', 'portal',
                'news', 'forum', 'wiki', 'beta', 'demo', 'old', 'new', 'web', 'email'
            ]
        
        found_subdomains = []
        print(f"\n{Fore.YELLOW}[🔍] Subdomain keşfi başlatıldı...")
        logger.info(f"Subdomain keşfi başladı: {domain} ({len(wordlist)} kelime)")
        
        for subdomain in wordlist:
            full_domain = f"{subdomain}.{domain}"
            ips = self.get_a_records(full_domain)
            
            if ips:
                found_subdomains.append({
                    'subdomain': full_domain,
                    'ips': ips
                })
                print(f"{Fore.GREEN}[+] Bulunan: {full_domain} -> {', '.join(ips)}")
        
        logger.info(f"Subdomain keşfi tamamlandı: {len(found_subdomains)} subdomain bulundu")
        return found_subdomains
    
    def analyze_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Tüm DNS kayıtlarını analiz eder"""
        logger.info(f"DNS analizi başladı: {domain}")
        return {
            "A": self.get_a_records(domain),
            "AAAA": self.get_aaaa_records(domain),
            "CNAME": self.get_cname_records(domain),
            "MX": self.get_mx_records(domain),
            "NS": self.get_ns_records(domain),
            "TXT": self.get_txt_records(domain)
        }
    
    def analyze_ip_addresses(self, ip_list: List[str], include_geoip: bool = False, 
                           include_reverse: bool = False) -> List[Dict[str, Any]]:
        """IP adreslerini analiz eder"""
        ip_analysis_results = []
        logger.info(f"IP analizi başladı: {len(ip_list)} IP adresi")
        
        for ip in ip_list:
            ip_info = {"ip": ip}
            print(f"\n{Fore.YELLOW}[🔍] IP Adresi: {ip}")
            
            if include_reverse:
                reverse_dns = self.get_reverse_dns(ip)
                ip_info["reverse_dns"] = reverse_dns
                if reverse_dns:
                    print(f"{Fore.GREEN}[+] Reverse DNS: {reverse_dns}")
                else:
                    print(f"{Fore.RED}[-] Reverse DNS: Bulunamadı")
            
            if include_geoip:
                geo_info = self.get_geoip_info(ip)
                ip_info["geo_info"] = geo_info
                if geo_info:
                    print(f"{Fore.GREEN}[+] Konum: {geo_info['city']}, {geo_info['region']}, {geo_info['country']}")
                    print(f"{Fore.GREEN}[+] ISP: {geo_info['isp']}")
                    print(f"{Fore.GREEN}[+] Organizasyon: {geo_info['org']}")
                    print(f"{Fore.GREEN}[+] AS: {geo_info['as']}")
                    print(f"{Fore.GREEN}[+] Koordinatlar: {geo_info['lat']}, {geo_info['lon']}")
                else:
                    print(f"{Fore.RED}[-] GeoIP Bilgisi: Alınamadı")
            
            ip_analysis_results.append(ip_info)
        
        return ip_analysis_results
    
    def display_dns_results(self, domain: str, dns_records: Dict[str, List[str]]) -> None:
        """DNS sonuçlarını ekranda gösterir"""
        self.print_header("DNS ANALİZİ")
        print(f"{Fore.YELLOW}[+] Domain: {domain}")
        
        record_types = [
            ("A", "A Kayıtları (IPv4)"),
            ("AAAA", "AAAA Kayıtları (IPv6)"),
            ("CNAME", "CNAME Kayıtları"),
            ("MX", "MX Kayıtları"),
            ("NS", "NS Kayıtları"),
            ("TXT", "TXT Kayıtları")
        ]
        
        for record_type, label in record_types:
            records = dns_records[record_type]
            if record_type == "TXT":
                print(f"{Fore.GREEN}[+] {label}: {len(records)} adet")
                if records:
                    for i, txt in enumerate(records, 1):
                        truncated_txt = txt[:100] + '...' if len(txt) > 100 else txt
                        print(f"    {Fore.CYAN}  [{i}] {truncated_txt}")
            else:
                print(f"{Fore.GREEN}[+] {label}: {', '.join(records) if records else 'Yok'}")
    
    def display_whois_results(self, whois_info: Dict[str, Any]) -> None:
        """WHOIS sonuçlarını ekranda gösterir"""
        self.print_header("WHOIS ANALİZİ")
        
        if 'error' not in whois_info:
            info_items = [
                ("Registrar", whois_info['registrar']),
                ("Kayıt Tarihi", whois_info['creation_date']),
                ("Son Kullanma Tarihi", whois_info['expiration_date']),
                ("Son Güncelleme", whois_info['updated_date']),
                ("Organizasyon", whois_info['org']),
                ("Ülke", whois_info['country'])
            ]
            
            for label, value in info_items:
                print(f"{Fore.GREEN}[+] {label}: {value}")
            
            if whois_info['emails']:
                print(f"{Fore.GREEN}[+] E-posta: {', '.join(whois_info['emails'])}")
        else:
            print(f"{Fore.RED}[-] WHOIS Hatası: {whois_info['error']}")
    
    def save_results_to_file(self, domain: str, results: Dict[str, Any], 
                           filename: Optional[str] = None) -> bool:
        """Sonuçları JSON formatında dosyaya kaydeder"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"dns_analysis_{domain}_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=JSON_INDENT, ensure_ascii=False)
            print(f"\n{Fore.CYAN}[💾] Sonuçlar kaydedildi: {filename}")
            logger.info(f"Sonuçlar başarıyla kaydedildi: {filename}")
            return True
        except (IOError, OSError) as e:
            error_msg = f"Dosya kaydetme hatası: {e}"
            print(f"\n{Fore.RED}[❌] {error_msg}")
            logger.error(error_msg)
            return False


class CLIManager:
    """Komut satırı arayüzünü yöneten sınıf"""
    
    def __init__(self, verbose: bool = False):
        self.analyzer = DNSAnalyzer(verbose)
        self.verbose = verbose
    
    def create_argument_parser(self) -> argparse.ArgumentParser:
        """Argüman parser'ını oluşturur"""
        parser = argparse.ArgumentParser(
            description="DNS ve IP Analiz Aracı",
            epilog="Örnek kullanım: python main.py --domain example.com --all --output sonuc.json"
        )
        
        parser.add_argument(
            "--domain", required=True, 
            help="Hedef domain adı (örnek: example.com)"
        )
        parser.add_argument(
            "--output", "-o", 
            help="Sonuçları JSON dosyasına kaydet (dosya adı)"
        )
        parser.add_argument(
            "--geoip", action="store_true", 
            help="IP adreslerinin GeoIP analizini yap"
        )
        parser.add_argument(
            "--reverse", action="store_true", 
            help="Reverse DNS sorgulaması yap"
        )
        parser.add_argument(
            "--whois", action="store_true", 
            help="Domain için WHOIS sorgulaması yap"
        )
        parser.add_argument(
            "--subdomains", action="store_true", 
            help="Temel subdomain keşfi yap"
        )
        parser.add_argument(
            "--all", action="store_true", 
            help="Tüm analizleri yap (geoip, reverse, whois, subdomains)"
        )
        parser.add_argument(
            "--verbose", "-v", action="store_true",
            help="Detaylı log çıktısı"
        )
        
        return parser
    
    def process_arguments(self, args: argparse.Namespace) -> None:
        """Argümanları işler ve --all parametresini genişletir"""
        if args.all:
            args.geoip = True
            args.reverse = True
            args.whois = True
            args.subdomains = True
    
    def run_analysis(self, args: argparse.Namespace) -> None:
        """Ana analiz işlemini çalıştırır"""
        domain = args.domain
        logger.info(f"Analiz başladı: {domain}")
        
        # Sonuçları saklayacağımız dict
        results = {
            "domain": domain,
            "scan_time": datetime.now().isoformat(),
            "dns_records": {},
            "ip_analysis": [],
            "whois_info": {},
            "subdomains": []
        }
        
        try:
            # DNS Analizi
            dns_records = self.analyzer.analyze_dns_records(domain)
            results["dns_records"] = dns_records
            self.analyzer.display_dns_results(domain, dns_records)
            
            # WHOIS Analizi
            if args.whois:
                whois_info = self.analyzer.get_whois_info(domain)
                results["whois_info"] = whois_info
                self.analyzer.display_whois_results(whois_info)
            
            # IP Analizi
            a_records = dns_records["A"]
            if (args.geoip or args.reverse) and a_records:
                self.analyzer.print_header("IP ADRESLERİ ANALİZİ")
                ip_analysis = self.analyzer.analyze_ip_addresses(
                    a_records, args.geoip, args.reverse
                )
                results["ip_analysis"] = ip_analysis
            
            # Subdomain Discovery
            if args.subdomains:
                self.analyzer.print_header("SUBDOMAIN KEŞFİ")
                subdomains = self.analyzer.discover_subdomains(domain)
                results["subdomains"] = subdomains
                
                if subdomains:
                    print(f"\n{Fore.GREEN}[✅] {len(subdomains)} subdomain bulundu!")
                else:
                    print(f"\n{Fore.RED}[-] Hiç subdomain bulunamadı.")
            
            # Sonuçları dosyaya kaydet
            if args.output:
                self.analyzer.save_results_to_file(domain, results, args.output)
            
            # Kapanış mesajları
            self._display_completion_message(args)
            logger.info(f"Analiz tamamlandı: {domain}")
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[⚠️] Kullanıcı tarafından iptal edildi")
            logger.info("Analiz kullanıcı tarafından iptal edildi")
        except Exception as e:
            error_msg = f"Beklenmeyen hata: {e}"
            print(f"\n{Fore.RED}[❌] {error_msg}")
            logger.error(error_msg)
            raise DNSAnalyzerException(error_msg)
    
    def _display_completion_message(self, args: argparse.Namespace) -> None:
        """Tamamlanma mesajlarını gösterir"""
        print(f"\n{Fore.CYAN}{'='*50}")
        print(f"{Fore.YELLOW}[✅] Analiz tamamlandı!")
        
        if not args.output:
            print(f"{Fore.CYAN}[💡] Sonuçları dosyaya kaydetmek için --output parametresini kullanın")
        
        suggestions = [
            "Tüm analizler için --all parametresini kullanın",
            "Detaylı log için --verbose parametresini kullanın", 
            "WHOIS analizi için --whois parametresini kullanın",
            "Subdomain keşfi için --subdomains parametresini kullanın"
        ]
        
        for suggestion in suggestions:
            print(f"{Fore.CYAN}[💡] {suggestion}")


def main() -> None:
    """Ana uygulama giriş noktası"""
    try:
        # İlk argüman parsing (verbose kontrolü için)
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--verbose", "-v", action="store_true")
        args, _ = parser.parse_known_args()
        
        # CLI manager'ı oluştur
        cli_manager = CLIManager(verbose=args.verbose)
        
        # Tam argüman parsing
        parser = cli_manager.create_argument_parser()
        args = parser.parse_args()
        
        # Argümanları işle
        cli_manager.process_arguments(args)
        
        # Analizi çalıştır
        cli_manager.run_analysis(args)
        
    except DNSAnalyzerException:
        exit(1)
    except Exception as e:
        logger.error(f"Kritik hata: {e}")
        print(f"\n{Fore.RED}[💀] Kritik hata oluştu. Lütfen log dosyasını kontrol edin.")
        exit(1)


if __name__ == "__main__":
    main()
