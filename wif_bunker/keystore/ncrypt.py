"""Win32 CNG (NCrypt) ctypes bindings for TPM key operations.

All direct Win32 API calls for key lifecycle management are isolated in
this module.  The rest of the codebase never touches ctypes/wintypes
directly for key operations.

This module is ONLY imported on Windows (``sys.platform == 'win32'``).
On macOS and Linux it exists on disk but is never loaded.

References:
  NCrypt API overview:
    https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/
  NCryptCreatePersistedKey:
    https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey
  NCryptExportKey:
    https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptexportkey
  BCRYPT_RSAKEY_BLOB / BCRYPT_ECCKEY_BLOB:
    https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob

How ctypes works (for future maintainers):
  Python's ``ctypes`` module calls functions in pre-compiled Windows DLLs
  (like ncrypt.dll) at runtime.  No C compiler is needed — these DLLs ship
  with every Windows installation.  Think of it as calling a function in a
  shared library, similar to how Python's ``ssl`` module calls libssl.
"""

from __future__ import annotations

import logging
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CNG / NCrypt constants
# ---------------------------------------------------------------------------

# Key Storage Providers — the TPM provider is preferred; the software
# provider is the fallback for --soft-key mode.
MS_PLATFORM_CRYPTO_PROVIDER = "Microsoft Platform Crypto Provider"
MS_SOFTWARE_KSP = "Microsoft Software Key Storage Provider"

# Algorithm identifiers for NCryptCreatePersistedKey
# https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers
BCRYPT_RSA_ALGORITHM = "RSA"
BCRYPT_ECDSA_P256_ALGORITHM = "ECDSA_P256"
BCRYPT_ECDSA_P384_ALGORITHM = "ECDSA_P384"

# Blob type strings for NCryptExportKey
BCRYPT_RSAPUBLIC_BLOB = "RSAPUBLICBLOB"
BCRYPT_ECCPUBLIC_BLOB = "ECCPUBLICBLOB"

# BCRYPT_RSAKEY_BLOB magic value for public keys
_BCRYPT_RSAPUBLIC_MAGIC = 0x31415352  # "RSA1" in little-endian ASCII

# BCRYPT_ECCKEY_BLOB magic values
_BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 0x31534345  # "ECS1"
_BCRYPT_ECDSA_PUBLIC_P384_MAGIC = 0x33534345  # "ECS3"

# NTSTATUS / SECURITY_STATUS error codes
_NTE_BAD_KEYSET = 0x80090016  # "keyset does not exist" — key not found
_NTE_EXISTS = 0x8009000F  # key container already exists

# NCryptCreatePersistedKey flags — these are NOT mutually exclusive
_NCRYPT_OVERWRITE_KEY_FLAG = 0x00000080


def _load_ctypes():
    """Lazy-load ctypes and wintypes (only available on Windows).

    Returns:
        Tuple of (ctypes_module, wintypes_module, ncrypt_dll).

    Raises:
        RuntimeError: if not running on Windows or ncrypt.dll cannot be loaded.
    """
    try:
        import ctypes  # pylint: disable=import-outside-toplevel
        from ctypes import wintypes  # pylint: disable=import-outside-toplevel
    except ImportError as exc:
        raise RuntimeError("ctypes.wintypes not available — this module requires Windows") from exc

    try:
        ncrypt = ctypes.windll.ncrypt  # type: ignore[attr-defined]
    except (AttributeError, OSError) as exc:
        raise RuntimeError(f"Could not load ncrypt.dll: {exc}") from exc

    return ctypes, wintypes, ncrypt


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_tpm_key(
    key_name: str,
    algorithm: str,
    key_length: int | None = None,
    soft_key: bool = False,
) -> int:
    """Create a persistent key in the TPM (or software KSP) via NCrypt.

    The key is created with non-exportable storage and is persisted in the
    Key Storage Provider so it survives reboots.

    Args:
        key_name: CNG key container name (e.g. "bunker-workload-1234").
        algorithm: CNG algorithm identifier — one of ``BCRYPT_RSA_ALGORITHM``,
            ``BCRYPT_ECDSA_P256_ALGORITHM``, or ``BCRYPT_ECDSA_P384_ALGORITHM``.
        key_length: Key size in bits.  Required for RSA (e.g. 2048).
            Ignored for ECC (key size is implicit in the algorithm).
        soft_key: If True, use the software KSP instead of the TPM.
            This is for --soft-key mode (development/testing).

    Returns:
        An NCrypt key handle (integer).  The caller is responsible for
        calling ``free_object(handle)`` when done.

    Raises:
        RuntimeError: if any NCrypt call fails.
    """
    ctypes, wintypes, ncrypt = _load_ctypes()

    provider_name = MS_SOFTWARE_KSP if soft_key else MS_PLATFORM_CRYPTO_PROVIDER
    provider_handle = wintypes.HANDLE()
    key_handle = wintypes.HANDLE()

    try:
        # 1. Open the Key Storage Provider.
        status = ncrypt.NCryptOpenStorageProvider(
            ctypes.byref(provider_handle),
            provider_name,
            0,
        )
        if status != 0:
            raise RuntimeError(f"NCryptOpenStorageProvider('{provider_name}') failed: 0x{status & 0xFFFFFFFF:08X}")

        # 2. Create a persisted key.
        #    NCryptCreatePersistedKey creates a key handle but does NOT
        #    persist it until NCryptFinalizeKey is called.
        #    NCRYPT_OVERWRITE_KEY_FLAG ensures idempotency if the key
        #    container already exists (e.g. from a failed previous run).
        status = ncrypt.NCryptCreatePersistedKey(
            provider_handle,
            ctypes.byref(key_handle),
            algorithm,
            key_name,
            0,  # dwLegacyKeySpec — 0 for CNG keys
            _NCRYPT_OVERWRITE_KEY_FLAG,
        )
        if status != 0:
            raise RuntimeError(
                f"NCryptCreatePersistedKey('{algorithm}', '{key_name}') failed: 0x{status & 0xFFFFFFFF:08X}"
            )

        # 3. Set key length (RSA only — ECC key size is determined by the
        #    algorithm identifier, e.g. ECDSA_P256 implies 256 bits).
        if key_length is not None:
            length_dword = wintypes.DWORD(key_length)
            status = ncrypt.NCryptSetProperty(
                key_handle,
                "Length",
                ctypes.byref(length_dword),
                ctypes.sizeof(length_dword),
                0,
            )
            if status != 0:
                raise RuntimeError(f"NCryptSetProperty('Length', {key_length}) failed: 0x{status & 0xFFFFFFFF:08X}")

        # 4. Mark the key as non-exportable.
        #    NCRYPT_ALLOW_EXPORT_FLAG = 0x1 → we set to 0 (no export).
        export_policy = wintypes.DWORD(0)
        status = ncrypt.NCryptSetProperty(
            key_handle,
            "Export Policy",
            ctypes.byref(export_policy),
            ctypes.sizeof(export_policy),
            0,
        )
        if status != 0:
            raise RuntimeError(f"NCryptSetProperty('Export Policy') failed: 0x{status & 0xFFFFFFFF:08X}")

        # 5. Finalize (persist) the key.
        #    After this call, the key is stored in the TPM / software KSP
        #    and survives reboots.
        #
        #    NOTE: We intentionally do NOT set PCP_KEY_USAGE_POLICY here.
        #    Setting NCRYPT_PCP_IDENTITY_KEY (0x8) would make this a
        #    "restricted signing key" that can ONLY sign TPM-internal
        #    structures (attestation blobs).  The workload key needs to
        #    sign arbitrary data (TLS handshakes via ECP), so it must
        #    remain an unrestricted signing key.
        #
        #    Attestation is handled by a separate Attestation Key (AK)
        #    created in attestation/windows.py, which IS an identity key.
        status = ncrypt.NCryptFinalizeKey(key_handle, 0)
        if status != 0:
            raise RuntimeError(f"NCryptFinalizeKey failed: 0x{status & 0xFFFFFFFF:08X}")

        logger.info(
            "    TPM key created: '%s' (%s) in %s",
            key_name,
            algorithm,
            provider_name,
        )

        # Transfer ownership of key_handle to the caller.
        handle_value = key_handle.value
        key_handle = wintypes.HANDLE()  # prevent cleanup from freeing it
        return handle_value

    finally:
        if key_handle.value:
            ncrypt.NCryptFreeObject(key_handle)
        if provider_handle.value:
            ncrypt.NCryptFreeObject(provider_handle)


def export_public_key_pem(key_handle: int, algorithm: str) -> str:
    """Export the public key from an NCrypt key handle as PEM.

    Calls NCryptExportKey to get the raw BCRYPT blob, then parses the
    blob into a ``cryptography`` public key object and serializes to PEM.

    Args:
        key_handle: NCrypt key handle from ``create_tpm_key`` or ``open_key``.
        algorithm: The CNG algorithm identifier (needed to select the
            correct blob format — RSA vs ECC).

    Returns:
        PEM-encoded public key string (SubjectPublicKeyInfo format).
    """
    ctypes, wintypes, ncrypt = _load_ctypes()

    # Select the right blob type based on algorithm.
    if algorithm == BCRYPT_RSA_ALGORITHM:
        blob_type = BCRYPT_RSAPUBLIC_BLOB
    else:
        blob_type = BCRYPT_ECCPUBLIC_BLOB

    handle = wintypes.HANDLE(key_handle)

    # First call: get required buffer size.
    blob_size = wintypes.DWORD(0)
    status = ncrypt.NCryptExportKey(
        handle,
        None,  # no export key (plaintext export)
        blob_type,
        None,  # no parameter list
        None,  # output buffer (null for size query)
        0,
        ctypes.byref(blob_size),
        0,
    )
    if status != 0:
        raise RuntimeError(f"NCryptExportKey size query failed: 0x{status & 0xFFFFFFFF:08X}")

    # Second call: export into allocated buffer.
    # NOTE: c_ubyte (unsigned 0-255), NOT c_byte (signed -128..127).
    # bytes() requires unsigned values; c_byte causes "bytes must be
    # in range(0, 256)" errors when any byte exceeds 127.
    blob_buffer = (ctypes.c_ubyte * blob_size.value)()
    result_size = wintypes.DWORD(0)
    status = ncrypt.NCryptExportKey(
        handle,
        None,
        blob_type,
        None,
        blob_buffer,
        blob_size.value,
        ctypes.byref(result_size),
        0,
    )
    if status != 0:
        raise RuntimeError(f"NCryptExportKey failed: 0x{status & 0xFFFFFFFF:08X}")

    blob_bytes = bytes(blob_buffer[: result_size.value])

    # Parse the BCRYPT blob into a cryptography public key.
    if algorithm == BCRYPT_RSA_ALGORITHM:
        pub_key = _parse_rsa_public_blob(blob_bytes)
    else:
        pub_key = _parse_ecc_public_blob(blob_bytes, algorithm)

    # Serialize to PEM.
    pem_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_bytes.decode("utf-8")


def delete_key(key_name: str, soft_key: bool = False) -> bool:
    """Delete a persisted key by name.

    Args:
        key_name: CNG key container name.
        soft_key: If True, look in the software KSP.

    Returns:
        True if the key was deleted, False if it didn't exist.
    """
    ctypes, wintypes, ncrypt = _load_ctypes()

    provider_name = MS_SOFTWARE_KSP if soft_key else MS_PLATFORM_CRYPTO_PROVIDER
    provider_handle = wintypes.HANDLE()
    key_handle = wintypes.HANDLE()

    try:
        status = ncrypt.NCryptOpenStorageProvider(
            ctypes.byref(provider_handle),
            provider_name,
            0,
        )
        if status != 0:
            return False

        status = ncrypt.NCryptOpenKey(
            provider_handle,
            ctypes.byref(key_handle),
            key_name,
            0,
            0,
        )
        if status != 0:
            # Key doesn't exist — nothing to delete.
            return False

        # NCryptDeleteKey frees the handle AND deletes the key.
        # Do NOT call NCryptFreeObject on the handle after this.
        status = ncrypt.NCryptDeleteKey(key_handle, 0)
        key_handle = wintypes.HANDLE()  # prevent double-free in finally
        if status != 0:
            logger.warning(
                "NCryptDeleteKey('%s') failed: 0x%08X",
                key_name,
                status & 0xFFFFFFFF,
            )
            return False

        logger.info("    Deleted TPM key: '%s'", key_name)
        return True

    finally:
        if key_handle.value:
            ncrypt.NCryptFreeObject(key_handle)
        if provider_handle.value:
            ncrypt.NCryptFreeObject(provider_handle)


def open_key(key_name: str, soft_key: bool = False) -> int | None:
    """Open an existing persisted key by name.

    Args:
        key_name: CNG key container name.
        soft_key: If True, look in the software KSP.

    Returns:
        NCrypt key handle (integer) if found, None if the key doesn't exist.
        The caller is responsible for calling ``free_object(handle)`` when done.
    """
    ctypes, wintypes, ncrypt = _load_ctypes()

    provider_name = MS_SOFTWARE_KSP if soft_key else MS_PLATFORM_CRYPTO_PROVIDER
    provider_handle = wintypes.HANDLE()
    key_handle = wintypes.HANDLE()

    try:
        status = ncrypt.NCryptOpenStorageProvider(
            ctypes.byref(provider_handle),
            provider_name,
            0,
        )
        if status != 0:
            return None

        status = ncrypt.NCryptOpenKey(
            provider_handle,
            ctypes.byref(key_handle),
            key_name,
            0,
            0,
        )
        if status != 0:
            return None

        handle_value = key_handle.value
        key_handle = wintypes.HANDLE()  # prevent cleanup
        return handle_value

    finally:
        if key_handle.value:
            ncrypt.NCryptFreeObject(key_handle)
        if provider_handle.value:
            ncrypt.NCryptFreeObject(provider_handle)


def free_object(handle: int) -> None:
    """Free an NCrypt handle (key or provider).

    Safe to call with 0 or None — does nothing.
    """
    if not handle:
        return
    _, wintypes, ncrypt = _load_ctypes()
    ncrypt.NCryptFreeObject(wintypes.HANDLE(handle))


# ---------------------------------------------------------------------------
# BCRYPT blob parsers (internal)
# ---------------------------------------------------------------------------


def _parse_rsa_public_blob(blob: bytes) -> rsa.RSAPublicKey:
    """Parse a BCRYPT_RSAPUBLIC_BLOB into a cryptography RSAPublicKey.

    Blob layout (all little-endian):
      +-------------------------------------------+
      | BCRYPT_RSAKEY_BLOB header (24 bytes)      |
      |   Magic        (4 bytes) = 0x31415352     |
      |   BitLength    (4 bytes)                  |
      |   cbPublicExp  (4 bytes)                  |
      |   cbModulus    (4 bytes)                  |
      |   cbPrime1     (4 bytes) = 0 (public)     |
      |   cbPrime2     (4 bytes) = 0 (public)     |
      +-------------------------------------------+
      | PublicExponent (cbPublicExp bytes)         |
      | Modulus        (cbModulus bytes)           |
      +-------------------------------------------+

    Reference:
      https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
    """
    if len(blob) < 24:
        raise ValueError(f"RSA public blob too short: {len(blob)} bytes")

    magic, _bit_length, cb_exp, cb_mod, _cb_p1, _cb_p2 = struct.unpack_from("<6I", blob, 0)
    if magic != _BCRYPT_RSAPUBLIC_MAGIC:
        raise ValueError(f"Bad RSA blob magic: 0x{magic:08X}")

    offset = 24
    exp_bytes = blob[offset : offset + cb_exp]
    offset += cb_exp
    mod_bytes = blob[offset : offset + cb_mod]

    exponent = int.from_bytes(exp_bytes, byteorder="big")
    modulus = int.from_bytes(mod_bytes, byteorder="big")

    return rsa.RSAPublicNumbers(e=exponent, n=modulus).public_key()


def _parse_ecc_public_blob(blob: bytes, algorithm: str) -> ec.EllipticCurvePublicKey:
    """Parse a BCRYPT_ECCPUBLIC_BLOB into a cryptography EllipticCurvePublicKey.

    Blob layout (all little-endian):
      +-------------------------------------------+
      | BCRYPT_ECCKEY_BLOB header (8 bytes)       |
      |   dwMagic  (4 bytes)                      |
      |   cbKey    (4 bytes) = coordinate size    |
      +-------------------------------------------+
      | X coordinate  (cbKey bytes, big-endian)   |
      | Y coordinate  (cbKey bytes, big-endian)   |
      +-------------------------------------------+

    Reference:
      https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
    """
    if len(blob) < 8:
        raise ValueError(f"ECC public blob too short: {len(blob)} bytes")

    magic, cb_key = struct.unpack_from("<2I", blob, 0)

    # Select curve based on algorithm.
    if algorithm == BCRYPT_ECDSA_P256_ALGORITHM:
        curve: ec.EllipticCurve = ec.SECP256R1()
        expected_magic = _BCRYPT_ECDSA_PUBLIC_P256_MAGIC
    elif algorithm == BCRYPT_ECDSA_P384_ALGORITHM:
        curve = ec.SECP384R1()
        expected_magic = _BCRYPT_ECDSA_PUBLIC_P384_MAGIC
    else:
        raise ValueError(f"Unsupported ECC algorithm: {algorithm}")

    if magic != expected_magic:
        raise ValueError(f"Bad ECC blob magic: 0x{magic:08X} (expected 0x{expected_magic:08X})")

    offset = 8
    x_bytes = blob[offset : offset + cb_key]
    offset += cb_key
    y_bytes = blob[offset : offset + cb_key]

    x = int.from_bytes(x_bytes, byteorder="big")
    y = int.from_bytes(y_bytes, byteorder="big")

    return ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve).public_key()


# ---------------------------------------------------------------------------
# Certificate store operations (crypt32.dll)
# ---------------------------------------------------------------------------

# CertOpenStore constants
_CERT_STORE_PROV_SYSTEM_W = 10
_CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000

# CertAddCertificateContextToStore disposition
_CERT_STORE_ADD_REPLACE_EXISTING = 3

# CertSetCertificateContextProperty
_CERT_KEY_PROV_INFO_PROP_ID = 2

# X.509 ASN.1 encoding type
_X509_ASN_ENCODING = 0x00000001
_PKCS_7_ASN_ENCODING = 0x00010000
_ENCODING = _X509_ASN_ENCODING | _PKCS_7_ASN_ENCODING


def import_cert_to_store(
    cert_der: bytes,
    key_name: str,
    provider_name: str,
) -> None:
    """Import a DER certificate into CurrentUser\\My and bind it to a CNG key.

    This is the programmatic equivalent of ``certreq -accept``, but without
    requiring the issuing CA to be in the Root trust store.

    Uses crypt32.dll (ships with every Windows) to:
      1. Open the CurrentUser\\My certificate store
      2. Decode and add the DER certificate
      3. Set CERT_KEY_PROV_INFO_PROP_ID to bind the cert to the named
         CNG key container in the specified provider

    Args:
        cert_der: DER-encoded certificate bytes.
        key_name: CNG key container name (must match a persisted key).
        provider_name: KSP provider name (e.g. "Microsoft Platform Crypto Provider").

    Raises:
        RuntimeError: if any crypt32 call fails.

    Reference:
        https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certsetcertificatecontextproperty
    """
    ctypes, wintypes, _ = _load_ctypes()

    try:
        crypt32 = ctypes.windll.crypt32
    except (AttributeError, OSError) as exc:
        raise RuntimeError(f"Could not load crypt32.dll: {exc}") from exc

    # Define CRYPT_KEY_PROV_INFO structure.
    # https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_key_prov_info
    class CRYPT_KEY_PROV_INFO(ctypes.Structure):  # pylint: disable=invalid-name
        _fields_ = [  # noqa: RUF012  — ctypes requires mutable class attr
            ("pwszContainerName", wintypes.LPWSTR),
            ("pwszProvName", wintypes.LPWSTR),
            ("dwProvType", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("cProvParam", wintypes.DWORD),
            ("rgProvParam", ctypes.c_void_p),  # PCRYPT_KEY_PROV_PARAM (unused)
            ("dwKeySpec", wintypes.DWORD),
        ]

    # ---------------------------------------------------------------
    # Declare argtypes/restype for every crypt32 function we call.
    # WITHOUT these, ctypes defaults to c_int (32-bit) for return
    # values.  On 64-bit Windows, HCERTSTORE and PCCERT_CONTEXT are
    # 64-bit pointers — truncating them to 32 bits causes an access
    # violation (segfault) when the pointer is later dereferenced.
    # ---------------------------------------------------------------

    # HCERTSTORE CertOpenStore(LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, const void*)
    crypt32.CertOpenStore.argtypes = [
        ctypes.c_void_p,  # lpszStoreProvider (int constant, not a real pointer)
        wintypes.DWORD,  # dwEncodingType
        ctypes.c_void_p,  # hCryptProv (NULL)
        wintypes.DWORD,  # dwFlags
        wintypes.LPCWSTR,  # pvPara (store name)
    ]
    crypt32.CertOpenStore.restype = ctypes.c_void_p  # HCERTSTORE (64-bit ptr)

    # PCCERT_CONTEXT CertCreateCertificateContext(DWORD, const BYTE*, DWORD)
    crypt32.CertCreateCertificateContext.argtypes = [
        wintypes.DWORD,  # dwCertEncodingType
        ctypes.c_char_p,  # pbCertEncoded (DER bytes)
        wintypes.DWORD,  # cbCertEncoded
    ]
    crypt32.CertCreateCertificateContext.restype = ctypes.c_void_p  # PCCERT_CONTEXT

    # BOOL CertAddCertificateContextToStore(HCERTSTORE, PCCERT_CONTEXT, DWORD, PCCERT_CONTEXT*)
    crypt32.CertAddCertificateContextToStore.argtypes = [
        ctypes.c_void_p,  # hCertStore
        ctypes.c_void_p,  # pCertContext
        wintypes.DWORD,  # dwAddDisposition
        ctypes.POINTER(ctypes.c_void_p),  # ppStoreContext (out)
    ]
    crypt32.CertAddCertificateContextToStore.restype = wintypes.BOOL

    # BOOL CertSetCertificateContextProperty(PCCERT_CONTEXT, DWORD, DWORD, const void*)
    crypt32.CertSetCertificateContextProperty.argtypes = [
        ctypes.c_void_p,  # pCertContext
        wintypes.DWORD,  # dwPropId
        wintypes.DWORD,  # dwFlags
        ctypes.c_void_p,  # pvData (pointer to CRYPT_KEY_PROV_INFO)
    ]
    crypt32.CertSetCertificateContextProperty.restype = wintypes.BOOL

    # BOOL CertFreeCertificateContext(PCCERT_CONTEXT)
    crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
    crypt32.CertFreeCertificateContext.restype = wintypes.BOOL

    # BOOL CertCloseStore(HCERTSTORE, DWORD)
    crypt32.CertCloseStore.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    crypt32.CertCloseStore.restype = wintypes.BOOL

    store_handle = None
    cert_context = None
    stored_context = None

    try:
        # 1. Open CurrentUser\My store.
        store_handle = crypt32.CertOpenStore(
            _CERT_STORE_PROV_SYSTEM_W,
            0,
            None,
            _CERT_SYSTEM_STORE_CURRENT_USER,
            "My",
        )
        if not store_handle:
            raise RuntimeError("CertOpenStore('My') failed")

        # 2. Create a certificate context from DER bytes.
        cert_context = crypt32.CertCreateCertificateContext(
            _ENCODING,
            cert_der,
            len(cert_der),
        )
        if not cert_context:
            raise RuntimeError("CertCreateCertificateContext failed")

        # 3. Add cert to store (replacing any existing cert with same key).
        stored_ptr = ctypes.c_void_p()
        ok = crypt32.CertAddCertificateContextToStore(
            store_handle,
            cert_context,
            _CERT_STORE_ADD_REPLACE_EXISTING,
            ctypes.byref(stored_ptr),
        )
        if not ok:
            raise RuntimeError("CertAddCertificateContextToStore failed")
        stored_context = stored_ptr.value

        # 4. Bind the cert to the CNG key container.
        #    CERT_KEY_PROV_INFO tells Windows where the private key lives.
        #    dwProvType = 0 means "CNG key" (not legacy CAPI).
        #    dwKeySpec = 0xFFFFFFFF (CERT_NCRYPT_KEY_SPEC) means "CNG key".
        key_prov_info = CRYPT_KEY_PROV_INFO(
            pwszContainerName=key_name,
            pwszProvName=provider_name,
            dwProvType=0,  # 0 = CNG provider
            dwFlags=0,
            cProvParam=0,
            rgProvParam=None,
            dwKeySpec=0xFFFFFFFF,  # CERT_NCRYPT_KEY_SPEC
        )
        ok = crypt32.CertSetCertificateContextProperty(
            stored_context,
            _CERT_KEY_PROV_INFO_PROP_ID,
            0,
            ctypes.addressof(key_prov_info),
        )
        if not ok:
            raise RuntimeError("CertSetCertificateContextProperty(CERT_KEY_PROV_INFO) failed")

        logger.info("    Cert imported to CurrentUser\\My and bound to key '%s'", key_name)

    finally:
        if stored_context:
            crypt32.CertFreeCertificateContext(stored_context)
        if cert_context:
            crypt32.CertFreeCertificateContext(cert_context)
        if store_handle:
            crypt32.CertCloseStore(store_handle, 0)
