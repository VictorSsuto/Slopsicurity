from .ssl_check import SSLScanner
from .headers import HeadersScanner
from .tech_detect import TechScanner
from .file_exposure import FileExposureScanner
from .dns_info import DNSScanner

ALL_SCANNERS = [
    SSLScanner,
    HeadersScanner,
    TechScanner,
    FileExposureScanner,
    DNSScanner,
]
