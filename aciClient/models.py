from dataclasses import dataclass, KW_ONLY

from requests.models import CaseInsensitiveDict


@dataclass
class Result:
    success: bool
    status_code: int
    message: str
    data: list
    headers: CaseInsensitiveDict


@dataclass
class AciCredentials:
    ip: str
    _token: KW_ONLY


@dataclass
class AciCredentialsPassword(AciCredentials):
    username: str
    password: str


@dataclass
class AciCredentialsCertificate(AciCredentials):
    pk_path: str
    cert_dn: str
