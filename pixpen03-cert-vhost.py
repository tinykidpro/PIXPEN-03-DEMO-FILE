#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
pixpen03-cert-vhost.py

PIXPEN-03 HTTPS Certificate Virtual Host Discovery Tool

Power by Shiina from Pixel Academy
"""

import argparse
import socket
import ssl
import sys
import textwrap
from typing import Dict, List, Tuple


BANNER = r"""
============================================================
 PIXPEN-03 HTTPS Certificate Virtual Host Discovery Tool
 Power by Shiina from Pixel Academy
============================================================
"""


HELP_TEXT = r"""
MỤC ĐÍCH CÔNG CỤ
  Công cụ này dùng để demo kỹ thuật HTTPS Certificate Virtual Host Discovery.

  Tool sẽ:
    1. Kết nối đến một HTTPS service.
    2. Lấy certificate mà server trả về.
    3. Phân tích các trường Common Name và Subject Alternative Name.
    4. Trích xuất các DNS Name có thể là virtual host candidate.
    5. Hiển thị quá trình phân tích bằng tiếng Việt.

  Ý tưởng chính:
    Nếu certificate liệt kê các DNS Name như:
      - admin.example.com
      - api.example.com
      - staging.example.com

    thì các tên này có thể là virtual host candidate để tester kiểm tra tiếp bằng:
      - dig
      - curl
      - browser
      - Burp Suite

CÁCH CHẠY CƠ BẢN
  Kiểm tra certificate của một domain online:

    python3 pixpen03-cert-vhost.py --host www.wikipedia.org

  Kiểm tra certificate của GitHub:

    python3 pixpen03-cert-vhost.py --host github.com

  Kiểm tra certificate của Google:

    python3 pixpen03-cert-vhost.py --host www.google.com

CHẠY VỚI IP VÀ SNI
  Một số web server cần SNI đúng hostname mới trả certificate phù hợp.

  Kết nối đến IP nhưng gửi SNI là domain:

    python3 pixpen03-cert-vhost.py --connect 93.184.216.34 --sni example.com

  Ý nghĩa:
    --connect 93.184.216.34  : IP hoặc host thực sự sẽ kết nối đến
    --sni example.com        : hostname gửi trong TLS handshake

CHẠY VỚI LAB LOCAL / SELF-SIGNED CERTIFICATE
  Nếu demo bằng certificate tự ký trong lab local:

    python3 pixpen03-cert-vhost.py --connect 127.0.0.1 --sni admin.pixpen03.local --insecure

  Lưu ý:
    --insecure dùng khi certificate không được CA tin cậy, ví dụ self-signed certificate.

CHỈ IN DANH SÁCH HOSTNAME
  Nếu chỉ muốn lấy danh sách hostname để pipe sang công cụ khác:

    python3 pixpen03-cert-vhost.py --host www.wikipedia.org --quiet

LƯU KẾT QUẢ RA FILE
  Lưu danh sách virtual host candidate:

    python3 pixpen03-cert-vhost.py --host www.wikipedia.org --out vhosts.txt

  Sau đó có thể xem:

    cat vhosts.txt

KIỂM TRA TIẾP CÁC HOSTNAME TÌM ĐƯỢC
  Kiểm tra DNS:

    while read host; do
      echo "[*] Checking DNS: $host"
      dig "$host" A +short
    done < vhosts.txt

  Kiểm tra HTTPS:

    while read host; do
      echo "[*] Checking HTTPS: $host"
      curl -k -I "https://$host/" --max-time 5
    done < vhosts.txt

VÍ DỤ OUTPUT MONG MUỐN
  [1] Common Name
      - admin.pixpen03.local

  [2] Subject Alternative Name - DNS Name
      - admin.pixpen03.local
      - api.pixpen03.local
      - staging.pixpen03.local
      - portal.pixpen03.local

  [3] Virtual Host Candidate
      - admin.pixpen03.local
      - api.pixpen03.local
      - staging.pixpen03.local
      - portal.pixpen03.local

GIẢI THÍCH NHANH
  Common Name:
    Trường hostname truyền thống trong certificate.

  Subject Alternative Name:
    Trường quan trọng hơn trong certificate hiện đại.
    Các DNS Name trong SAN thường là hostname hợp lệ của certificate.

  Virtual Host Candidate:
    Hostname có thể được web server dùng để phân biệt web application.
    Cần xác minh lại bằng DNS, HTTP/HTTPS và scope kiểm thử.

LƯU Ý AN TOÀN
  - Chỉ kiểm thử domain/IP nằm trong scope được phép.
  - Không dùng hostname tìm được để tấn công ngoài phạm vi.
  - Kết quả từ certificate chỉ là manh mối, không tự động là lỗ hổng.
"""


def print_banner() -> None:
    print(BANNER)


def print_long_help(parser: argparse.ArgumentParser) -> None:
    print_banner()
    print(HELP_TEXT)
    print("THAM SỐ HỖ TRỢ")
    print(parser.format_help())


class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        print_banner()
        print(f"[!] Lỗi tham số: {message}\n")
        print("Ví dụ chạy nhanh:")
        print("  python3 pixpen03-cert-vhost.py --host www.wikipedia.org")
        print("  python3 pixpen03-cert-vhost.py --host github.com")
        print("  python3 pixpen03-cert-vhost.py --connect 127.0.0.1 --sni admin.pixpen03.local --insecure\n")
        print("Dùng -h hoặc --help để xem hướng dẫn đầy đủ.")
        sys.exit(2)


def log_step(message: str, quiet: bool = False) -> None:
    if not quiet:
        print(f"[+] {message}")


def log_info(message: str, quiet: bool = False) -> None:
    if not quiet:
        print(f"    {message}")


def get_certificate(
    connect_host: str,
    port: int,
    sni: str,
    timeout: float,
    insecure: bool,
    quiet: bool,
) -> Dict:
    log_step("Bước 1: Chuẩn bị kết nối TLS đến server", quiet)
    log_info(f"Host/IP kết nối: {connect_host}", quiet)
    log_info(f"Port: {port}", quiet)
    log_info(f"SNI gửi trong TLS handshake: {sni}", quiet)

    context = ssl.create_default_context()

    if insecure:
        log_info("Chế độ --insecure đang bật: cho phép certificate tự ký hoặc không trusted", quiet)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    log_step("Bước 2: Thực hiện TLS handshake và lấy certificate từ server", quiet)

    with socket.create_connection((connect_host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=sni) as tls:
            cert = tls.getpeercert()
            if not cert:
                raise RuntimeError(
                    "Server không trả về certificate. Nếu đây là lab self-signed, hãy thử thêm --insecure."
                )

            log_info("Đã nhận được certificate từ server", quiet)
            return cert


def extract_common_names(cert: Dict) -> List[str]:
    names = []
    for item in cert.get("subject", []):
        for key, value in item:
            if key.lower() == "commonname":
                names.append(value)
    return sorted(set(names))


def extract_san_dns_names(cert: Dict) -> List[str]:
    names = []
    for key, value in cert.get("subjectAltName", []):
        if key.lower() == "dns":
            names.append(value)
    return sorted(set(names))


def extract_issuer(cert: Dict) -> List[Tuple[str, str]]:
    issuer_items = []
    for item in cert.get("issuer", []):
        for key, value in item:
            issuer_items.append((key, value))
    return issuer_items


def explain_certificate_analysis(common_names: List[str], san_names: List[str], quiet: bool) -> None:
    if quiet:
        return

    log_step("Bước 3: Phân tích các trường có thể làm lộ virtual host")

    print()
    print("    Giải thích:")
    print("    - Common Name từng là trường chính để thể hiện hostname của certificate.")
    print("    - Subject Alternative Name, đặc biệt là DNS Name, hiện là nơi quan trọng hơn.")
    print("    - Nếu certificate liệt kê nhiều DNS Name, các tên này có thể là virtual host candidate.")
    print("    - Tester có thể lấy các hostname này để kiểm tra DNS, HTTP/HTTPS và đưa vào Burp Suite.")
    print()

    if common_names:
        print("    Common Name tìm thấy:")
        for name in common_names:
            print(f"    - {name}")
    else:
        print("    Không tìm thấy Common Name.")

    print()

    if san_names:
        print("    DNS Name trong Subject Alternative Name tìm thấy:")
        for name in san_names:
            print(f"    - {name}")
    else:
        print("    Không tìm thấy DNS Name trong Subject Alternative Name.")


def is_wildcard(name: str) -> bool:
    return name.startswith("*.")


def classify_candidates(names: List[str]) -> Tuple[List[str], List[str]]:
    wildcard = []
    concrete = []

    for name in names:
        if is_wildcard(name):
            wildcard.append(name)
        else:
            concrete.append(name)

    return sorted(set(concrete)), sorted(set(wildcard))


def print_report(cert: Dict, common_names: List[str], san_names: List[str], quiet: bool = False) -> List[str]:
    candidates_all = sorted(set(common_names + san_names))
    concrete_candidates, wildcard_candidates = classify_candidates(candidates_all)

    if quiet:
        for name in concrete_candidates:
            print(name)
        for name in wildcard_candidates:
            print(name)
        return candidates_all

    print()
    print("=" * 72)
    print("BÁO CÁO PHÂN TÍCH HTTPS CERTIFICATE")
    print("=" * 72)

    print()
    print("[1] Thông tin certificate")
    print(f"    Có hiệu lực từ : {cert.get('notBefore', '<không rõ>')}")
    print(f"    Hết hạn vào    : {cert.get('notAfter', '<không rõ>')}")

    issuer = extract_issuer(cert)
    if issuer:
        print("    Issuer         :")
        for key, value in issuer:
            print(f"      - {key}: {value}")

    print()
    print("[2] Common Name")
    if common_names:
        for name in common_names:
            print(f"    - {name}")
    else:
        print("    - Không có hoặc không đọc được Common Name")

    print()
    print("[3] Subject Alternative Name - DNS Name")
    if san_names:
        for name in san_names:
            print(f"    - {name}")
    else:
        print("    - Không có DNS Name trong SAN")

    print()
    print("[4] Virtual Host Candidate")
    if concrete_candidates:
        print("    Hostname cụ thể có thể kiểm tra tiếp:")
        for name in concrete_candidates:
            print(f"    - {name}")
    else:
        print("    Không tìm thấy hostname cụ thể.")

    if wildcard_candidates:
        print()
        print("    Wildcard certificate:")
        for name in wildcard_candidates:
            print(f"    - {name}")
        print()
        print("    Lưu ý:")
        print("    - Wildcard như *.example.com cho biết có thể tồn tại nhiều subdomain.")
        print("    - Tuy nhiên nó không liệt kê từng hostname cụ thể.")
        print("    - Vì vậy wildcard certificate ít hữu ích hơn khi cần tìm virtual host cụ thể.")

    print()
    print("[5] Gợi ý bước kiểm tra tiếp theo")
    print("    - Kiểm tra DNS: dig <hostname> A")
    print("    - Kiểm tra HTTPS: curl -k -I https://<hostname>/")
    print("    - Kiểm tra nội dung web: mở hostname bằng browser hoặc đưa vào Burp Suite")
    print("    - Xác minh hostname có nằm trong scope kiểm thử hay không")

    print()
    print("=" * 72)

    return candidates_all


def save_names(path: str, names: List[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for name in names:
            f.write(name + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = CustomArgumentParser(
        prog="pixpen03-cert-vhost.py",
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Phân tích HTTPS certificate để tìm virtual host candidate.",
    )

    parser.add_argument("-h", "--help", action="store_true", help="Hiển thị hướng dẫn chi tiết")

    target = parser.add_mutually_exclusive_group()
    target.add_argument("--host", help="Hostname để kết nối và dùng làm SNI, ví dụ: www.wikipedia.org")
    target.add_argument("--connect", help="IP/hostname thực sự để kết nối, ví dụ: 127.0.0.1")

    parser.add_argument("--sni", help="SNI hostname gửi trong TLS handshake")
    parser.add_argument("--port", type=int, default=443, help="TLS port, mặc định là 443")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout kết nối, mặc định 5 giây")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Cho phép certificate tự ký hoặc không trusted, phù hợp cho lab local",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Chỉ in danh sách hostname, phù hợp để pipe sang công cụ khác",
    )
    parser.add_argument("--out", help="Lưu danh sách virtual host candidate ra file")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.help:
        print_long_help(parser)
        return 0

    if not args.host and not args.connect:
        print_banner()
        print("[!] Bạn chưa chỉ định mục tiêu cần phân tích.\n")
        print("Chạy nhanh với domain online:")
        print("  python3 pixpen03-cert-vhost.py --host www.wikipedia.org\n")
        print("Chạy với lab local self-signed:")
        print("  python3 pixpen03-cert-vhost.py --connect 127.0.0.1 --sni admin.pixpen03.local --insecure\n")
        print("Xem hướng dẫn đầy đủ:")
        print("  python3 pixpen03-cert-vhost.py --help")
        return 2

    if args.connect and not args.sni:
        print_banner()
        print("[!] Bạn đang dùng --connect nhưng chưa chỉ định --sni.\n")
        print("Khi kết nối bằng IP, nên chỉ định SNI để server trả đúng certificate.")
        print("Ví dụ:")
        print("  python3 pixpen03-cert-vhost.py --connect 93.184.216.34 --sni example.com")
        print("  python3 pixpen03-cert-vhost.py --connect 127.0.0.1 --sni admin.pixpen03.local --insecure")
        return 2

    connect_host = args.host or args.connect
    sni = args.sni or args.host or args.connect

    if not args.quiet:
        print_banner()

    try:
        cert = get_certificate(
            connect_host=connect_host,
            port=args.port,
            sni=sni,
            timeout=args.timeout,
            insecure=args.insecure,
            quiet=args.quiet,
        )

        common_names = extract_common_names(cert)
        san_names = extract_san_dns_names(cert)

        explain_certificate_analysis(common_names, san_names, args.quiet)

        candidates = print_report(cert, common_names, san_names, quiet=args.quiet)

        if args.out:
            save_names(args.out, candidates)
            if not args.quiet:
                print(f"\n[+] Đã lưu {len(candidates)} hostname candidate vào file: {args.out}")

        return 0

    except ssl.SSLCertVerificationError as e:
        print(f"[!] Lỗi xác minh TLS certificate: {e}", file=sys.stderr)
        print("[!] Nếu đang demo lab self-signed, hãy chạy lại với option --insecure", file=sys.stderr)
        return 2

    except socket.gaierror as e:
        print(f"[!] Không phân giải được host/SNI: {e}", file=sys.stderr)
        return 3

    except TimeoutError:
        print("[!] Kết nối bị timeout", file=sys.stderr)
        return 4

    except ConnectionRefusedError:
        print("[!] Kết nối bị từ chối. Kiểm tra host, port hoặc dịch vụ HTTPS.", file=sys.stderr)
        return 5

    except Exception as e:
        print(f"[!] Lỗi: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
