"""
PhishCloner Ultimate v1.0.0 — Engine Package
Signé Ghost1o1 — 9 engine modules
"""

__version__ = "1.0.0"
__author__ = "ghost1o1"
__codename__ = "GhostNet"

from .tls_spoofer import TLSSpoofer
from .mitm_proxy import MITMProxy
from .mfa_relay import MFARelay
from .cred_validator import CredentialValidator
from .exfil import ExfilEngine
from .delivery import DeliveryEngine
from .proxy_pool import ProxyPool, ProxiedMITMTransport
from .reporter import AutoReporter, CVSSCalculator
from .template_loader import TemplateLoader

__all__ = [
    "TLSSpoofer",
    "MITMProxy",
    "MFARelay",
    "CredentialValidator",
    "ExfilEngine",
    "DeliveryEngine",
    "ProxyPool",
    "ProxiedMITMTransport",
    "AutoReporter",
    "CVSSCalculator",
    "TemplateLoader",
]
