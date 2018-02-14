"""
This module contains everything related to the internal certificate authority of the VPN server.
Author: Sascha Falk <sascha@falk-online.eu>
License: MIT License
"""

import configparser
import os
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from glob import iglob
from OpenSSL import crypto, SSL
from cryptography import x509
from stat import S_IRUSR, S_IWUSR, S_IRGRP, S_IWGRP, S_IROTH, S_IWOTH
from ..cc_log import Log
from ..cc_helpers import is_email_address


# -------------------------------------------------------------------------------------------------------------------------------------------------------------
# Definitions
# -------------------------------------------------------------------------------------------------------------------------------------------------------------


CA_BASE_DIR = "/data/internal_ca"


# -------------------------------------------------------------------------------------------------------------------------------------------------------------
# Exception Classes
# -------------------------------------------------------------------------------------------------------------------------------------------------------------


class Error(Exception):
    """
    Base class for exceptions in this module.
    """
    pass


# -----------------------------------------------------------------------------------------------------------------------------------------


class NotInitializedError(Error):
    """
    Exception that is raised, if the CA is not initialized.

    Attributes:
        message (str) : Explanation of the error
    """

    def __init__(self, message, *args):
        self.message = message.format(*args)


# -----------------------------------------------------------------------------------------------------------------------------------------


class AlreadyInitializedError(Error):
    """
    Exception that is raised, if the CA is already initialized.

    Attributes:
        message (str) : Explanation of the error
    """

    def __init__(self, message, *args):
        self.message = message.format(*args)


# -----------------------------------------------------------------------------------------------------------------------------------------


class InconsistencyDetectedError(Error):
    """
    Exception that is raised, if the CA detects an inconsistency in its database.

    Attributes:
        message (str) : Explanation of the error
    """

    def __init__(self, message, *args):
        self.message = message.format(*args)


# -----------------------------------------------------------------------------------------------------------------------------------------


class PasswordRequiredError(Error):
    """
    Exception that is raised, if an operation requires the CA password and it is not set.

    Attributes:
        message (str) : Explanation of the error
    """

    def __init__(self, message, *args):
        self.message = message.format(*args)


# -----------------------------------------------------------------------------------------------------------------------------------------


class InvalidPasswordError(Error):
    """
    Exception that is raised, if a specified password does not match the CA password.

    Attributes:
        message (str) : Explanation of the error
    """

    def __init__(self, message, *args):
        self.message = message.format(*args)


# -----------------------------------------------------------------------------------------------------------------------------------------


class NotFoundError(Error):
    """
    Exception that is raised, if a requested item was not found.

    Attributes:
        message (str) : Explanation of the error
    """

    def __init__(self, message, *args):
        self.message = message.format(*args)


# -------------------------------------------------------------------------------------------------------------------------------------------------------------
# The KeyType/KeyTypes Class
# -------------------------------------------------------------------------------------------------------------------------------------------------------------


class KeyType:

    def __init__(self, name, description, factory):
        """
        Initializes the instance of the KeyType class.

        Args:
            name (str)        : Short name of the key type.
            description (str) : A more elaborate description of the key type.
            factory (func)    : A factory function creating a new key of the type.
        """

        self.__name = name
        self.__description = description
        self.__factory = factory

    @property
    def name(self):
        """
        Gets the name of the key type.

        """
        return self.__name

    @property
    def description(self):
        """
        Gets the description of the key type.

        """
        return self.__description

    @property
    def factory(self):
        """
        Gets the factory function creating a new key of the type.

        """
        return self.__factory

    def create_key(self):
        """
        Creates a key of the current type.

        """
        key = self.factory()
        key_pem = key.private_bytes(encoding = Encoding.PEM, format = PrivateFormat.TraditionalOpenSSL, encryption_algorithm = NoEncryption())
        return crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem)


class KeyTypes:

    rsa2048   = KeyType("rsa2048", "RSA, 2048 bit",                                                             lambda: rsa.generate_private_key(65537, 2048, default_backend()))
    rsa3072   = KeyType("rsa3072", "RSA, 3072 bit",                                                             lambda: rsa.generate_private_key(65537, 3072, default_backend()))
    rsa4096   = KeyType("rsa4096", "RSA, 4096 bit",                                                             lambda: rsa.generate_private_key(65537, 4096, default_backend()))
    secp192r1 = KeyType("secp192r1", "ECC, SECG curve over a 192 bit prime field (aka P-192, prime192v1)",      lambda: ec.generate_private_key(ec.SECP192R1, default_backend()))
    secp224r1 = KeyType("secp224r1", "ECC, NIST/SECG curve over a 224 bit prime field",                         lambda: ec.generate_private_key(ec.SECP224R1, default_backend()))
    secp256k1 = KeyType("secp256k1", "ECC, SECG curve over a 256 bit prime field",                              lambda: ec.generate_private_key(ec.SECP256K1, default_backend()))
    secp256r1 = KeyType("secp256r1", "ECC, NIST/SECG curve over a 256 bit prime field (aka P-256, prime256v1)", lambda: ec.generate_private_key(ec.SECP256R1, default_backend()))
    secp384r1 = KeyType("secp384r1", "ECC, NIST/SECG curve over a 384 bit prime field (aka P-384)",             lambda: ec.generate_private_key(ec.SECP384R1, default_backend()))
    secp521r1 = KeyType("secp521r1", "ECC, NIST/SECG curve over a 521 bit prime field (aka P-521)",             lambda: ec.generate_private_key(ec.SECP521R1, default_backend()))

    @classmethod
    def get_by_name(cls, name):
       name = name.lower()
       for kt in KeyTypes.all():
           if kt.name == name:
               return kt
       return None

    @classmethod
    def all(cls):
        yield KeyTypes.rsa2048
        yield KeyTypes.rsa3072
        yield KeyTypes.rsa4096
        yield KeyTypes.secp192r1
        yield KeyTypes.secp224r1
        yield KeyTypes.secp256k1
        yield KeyTypes.secp256r1
        yield KeyTypes.secp384r1
        yield KeyTypes.secp521r1


# -------------------------------------------------------------------------------------------------------------------------------------------------------------
# The CertificateAuthority Class
# -------------------------------------------------------------------------------------------------------------------------------------------------------------


class CertificateAuthority:


    # -------------------------------------------------------------------------------------------------------------------------------------


    def __init__(self):
        """
        Initializes the instance of the CertificateAuthority class.

        """

        self.__base_dir                 = CA_BASE_DIR
        self.__ca_key_path              = os.path.join(self.__base_dir, "ca-key.pem")
        self.__ca_cert_path             = os.path.join(self.__base_dir, "ca-cert.pem")
        self.__ca_crl_path              = os.path.join(self.__base_dir, "ca-crl.pem")
        self.__ca_config_path           = os.path.join(self.__base_dir, "ca-config.ini")
        self.__ca_next_cert_serial_path = os.path.join(self.__base_dir, "next-cert-serial.cnt")
        self.__storage_dir              = os.path.join(self.__base_dir, "storage")
        self.__ca_password              = None
        self.__inited                   = False

        self.__ca_specific_files = [
            self.__ca_key_path,
            self.__ca_cert_path,
            self.__ca_crl_path,
            self.__ca_config_path,
        ]


    # -------------------------------------------------------------------------------------------------------------------------------------


    @property
    def config(self):
        """
        Gets the configuration of the CA (configparser obj).

        """
        config = configparser.ConfigParser()
        config.read(self.__ca_config_path)
        return config


    # -------------------------------------------------------------------------------------------------------------------------------------


    @property
    def password(self):
        """
        Gets the password of the CA.

        """
        return self.__ca_password


    # -------------------------------------------------------------------------------------------------------------------------------------


    @password.setter
    def password(self, value):
        """
        Sets the password that is used to decrypt the private key of the CA.

        Args:
            value (str) : Password to set (may be None, if no password is needed).

        """

        if value != None and not type(value) is str:
            raise RuntimeError("Argument must be None or a string.")

        # condition password
        password = value
        if value:
            password = password.strip()
            if len(password) == 0: password = None

        # ensure that the environment is initialized, so the entered password can be checked
        if not self.is_inited():
            raise NotInitializedError("The CA is not initialized.")

        # try to decrypt the private key of the CA with the password
        try:

            with open(self.__ca_key_path, "rb") as f:
                if password == None: ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read(), b"")
                else:                ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read(), password.encode("utf-8"))

            self.__ca_password = password

        except crypto.Error as e:

            for arg in e.args:
                for error in arg:
                    if error[2] == "bad decrypt" or error[2] == "bad password read":
                        # decrypting private key failed
                        raise InvalidPasswordError("Decrypting CA private key failed. Wrong password.")

            # some other OpenSSL error occurred
            raise

    # -------------------------------------------------------------------------------------------------------------------------------------


    @property
    def password_required(self):
        """
        Checks whether a password is needed to decrypt the CA's private key.

        Returns:
            True, if a password is needed to decrypt the CA's private key, otherwise False.

        """

        if not self.is_inited():
            raise NotInitializedError("The CA is not initialized.")

        try:

            # try to read the private key without a password
            with open(self.__ca_key_path, "rb") as f:
                ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read(), b"")

        except crypto.Error as e:

            for arg in e.args:
                for error in arg:
                    if error[2] == "bad password read":
                        # private key is encrypted
                        return True

            # some other OpenSSL error occurred
            raise

        # private key is not encrypted
        return False


    # -------------------------------------------------------------------------------------------------------------------------------------


    @property
    def cert(self):
        """
        Loads the certificate of the CA.

        Exceptions:
            NotInitializedError : The CA environment is not initialized.

        """

        # ensure that the CA environment is initialized
        if not self.is_inited():
            raise NotInitializedError("The CA is not initialized.")

        # load the certificate
        with open(self.__ca_cert_path, "rb") as f:
            return crypto.load_certificate(crypto.FILETYPE_PEM, f.read())


    # -------------------------------------------------------------------------------------------------------------------------------------


    @property
    def cert_path(self):
        """
        Gets the path of the certificate of the CA.

        """
        return self.__ca_cert_path


    # -------------------------------------------------------------------------------------------------------------------------------------


    @property
    def key(self):
        """
        Loads the private key of the CA (the 'password' property must be set, if CA related data is encrypted).

        Exceptions:
            NotInitializedError : The CA environment is not initialized.

        """

        # ensure that the CA environment is initialized and the password is set, if necessary
        if self.password_required and not self.__ca_password:
            raise PasswordRequiredError("The requested operation requires the CA password to access the private key.")

        # try to decrypt the private key of the CA with the password
        with open(self.__ca_key_path, "rb") as f:
            if not self.__ca_password: return crypto.load_privatekey(crypto.FILETYPE_PEM, f.read(), b"")
            else:                      return crypto.load_privatekey(crypto.FILETYPE_PEM, f.read(), self.__ca_password.encode("utf-8"))


    # -------------------------------------------------------------------------------------------------------------------------------------


    @property
    def crl(self):
        """
        Loads the CRL of the CA.

        Exceptions:
            NotInitializedError : The CA environment is not initialized.

        """

        # ensure that the CA environment is initialized
        if not self.is_inited():
            raise NotInitializedError("The CA is not initialized.")

        # load the CRL
        with open(self.__ca_crl_path, "rb") as f:
            return crypto.load_crl(crypto.FILETYPE_PEM, f.read())


    # -------------------------------------------------------------------------------------------------------------------------------------


    @property
    def crl_path(self):
        """
        Gets the path of the CRL of the CA.

        """
        return self.__ca_crl_path


    # -------------------------------------------------------------------------------------------------------------------------------------


    def init(self, password, ca_key_type, server_key_type, client_key_type):
        """
        Initialized the CA environment generating related data (private key, certificate and filesystem structure).

        Args:
            password (str)        : Password to protect CA related data with (None, if you don't want to use any protection)
            ca_key_type (str)     : Type of the private key to create for the CA. See class 'KeyType' for supported key types.
            server_key_type (str) : Type of the private key to create for the server lateron. See class 'KeyType' for supported key types.
            client_key_type (str) : Type of the private key to use for clients created lateron. See class 'KeyType' for supported key types.

        Exceptions:
            AlreadyInitializedError : The CA is already initialized (associated files are already present).

        """

        # abort, if a file that belongs to the CA itself is already present
        # ---------------------------------------------------------------------
        if self.is_inited():
            raise AlreadyInitializedError("The CA is already initialized.")

        # create directories where the files are stored
        # ---------------------------------------------------------------------
        for ca_file in self.__ca_specific_files:
            os.makedirs(os.path.dirname(ca_file), exist_ok = True)

        # condition password
        # ---------------------------------------------------------------------
        if password:
            password = password.strip()
            if len(password) == 0: password = None

        # ensure that the specified key types are valid
        # ---------------------------------------------------------------------
        if not ca_key_type.lower() in [kt.name for kt in KeyTypes.all()]:
            raise ArgumentError("Invalid key type ({0})".format(ca_key_type))
        if not server_key_type.lower() in [kt.name for kt in KeyTypes.all()]:
            raise ArgumentError("Invalid key type ({0})".format(server_key_type))
        if not client_key_type.lower() in [kt.name for kt in KeyTypes.all()]:
            raise ArgumentError("Invalid key type ({0})".format(client_key_type))

        # create the CA's private key
        # ---------------------------------------------------------------------
        ca_key = KeyTypes.get_by_name(ca_key_type).create_key()

        # create the CA's certificate
        # ---------------------------------------------------------------------
        ca_cert = crypto.X509()
        ca_cert.get_subject().C  = "DE"
        ca_cert.get_subject().ST = "Berlin"
        ca_cert.get_subject().L  = "Berlin"
        ca_cert.get_subject().O  = "CloudyCube"
        ca_cert.get_subject().CN = "Internal CA for VPN"
        ca_cert.set_serial_number(self.get_next_serial_number())
        ca_cert.gmtime_adj_notBefore(0)
        ca_cert.gmtime_adj_notAfter(10*365*24*60*60)
        ca_cert.set_issuer(ca_cert.get_subject())
        ca_cert.set_pubkey(ca_key)
        ca_cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
            crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
        ])
        ca_cert.add_extensions([
          crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert)  
        ])

        ca_cert.sign(ca_key, "sha256")

        # create the CRL
        # ---------------------------------------------------------------------
        ski = ca_cert.to_cryptography().extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        ca_crl = x509.CertificateRevocationListBuilder() \
            .issuer_name(x509.Name([ x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
                                     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Berlin"),
                                     x509.NameAttribute(NameOID.LOCALITY_NAME, "Berlin"),
                                     x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CloudyCube"),
                                     x509.NameAttribute(NameOID.COMMON_NAME, "Internal CA for VPN") ])) \
            .last_update(datetime.today()) \
            .next_update(datetime.today() + timedelta(30,0,0)) \
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), False) \
            .sign(private_key = ca_key.to_cryptography_key(), algorithm=hashes.SHA256(), backend=default_backend())

        # write everything to disk
        # ---------------------------------------------------------------------
        try:

            # private key
            with open(self.__ca_key_path, "wb") as f:
               if password: f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key, "aes256", password.encode("utf-8")) )
               else:        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))
            os.chown(self.__ca_key_path, 0, 0)
            os.chmod(self.__ca_key_path, S_IRUSR | S_IWUSR)

            # certificate
            with open(self.__ca_cert_path, "wb") as f:
               f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
            os.chown(self.__ca_cert_path, 0, 0)
            os.chmod(self.__ca_cert_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

            # CRL
            with open(self.__ca_crl_path, "wb") as f:
                f.write(ca_crl.public_bytes(Encoding.PEM))
            os.chown(self.__ca_cert_path, 0, 0)
            os.chmod(self.__ca_cert_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

            # desired server/client key type
            config = configparser.ConfigParser()
            config["server"] = {}
            config["server"]["default-key-type"] = server_key_type.lower()
            config["client"] = {}
            config["client"]["default-key-type"] = client_key_type.lower()
            with open(self.__ca_config_path, "w") as configfile:
                config.write(configfile)
            os.chown(self.__ca_config_path, 0, 0)
            os.chmod(self.__ca_config_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

        except:

            # writing CA environment failed => delete generated files
            if os.path.exists(self.__ca_key_path): os.remove(self.__ca_key_path)
            if os.path.exists(self.__ca_cert_path): os.remove(self.__ca_cert_path)
            if os.path.exists(self.__ca_crl_path): os.remove(self.__ca_crl_path)
            if os.path.exists(self.__ca_config_path): os.remove(self.__ca_config_path)
            raise

        self.__ca_password = password


    # -------------------------------------------------------------------------------------------------------------------------------------


    def is_inited(self):
        """
        Checks whether the CA environment is initialized.

        Returns:
            True, if the CA environment is initialized; otherwise False.

        """

        count = 0
        for ca_file in self.__ca_specific_files:
            if os.path.exists(ca_file): count += 1

        if count > 0 and count != len(self.__ca_specific_files):
            raise InconsistencyDetectedError("The CA seems to be initialized, but there are files missing!")

        return count > 0


    # -------------------------------------------------------------------------------------------------------------------------------------


    def get_certificate(self, serial_number, raiseIfNotExist = True):
        """
        Gets the specified certificate.

        Args:
            serial_number (int)    : Serial number of the certificate to get.
            raiseIfNotExist (bool) : True to throw a NotFoundError exception, if the requested certificate does not exist;
                                     False to return None, if the requested certificate does not exist.

        Returns:
            An OpenSSL X509 certificate object;
            None, if the specified certificate does not exist (and raiseIfNotExist is False).

        Exceptions:
            NotFoundError, if the specified certificate does not exist (and raiseIfNotExist is True).

        """

        serial_number = int(serial_number)

        # ensure that the environment is initialized
        if not self.is_inited():
            raise NotInitializedError("The CA is not initialized.")

        # check whether the certificate exists
        filename = "{0:010}.crt".format(serial_number)
        cert_path = os.path.join(self.__storage_dir, filename)
        if not os.path.exists(cert_path):
            if raiseIfNotExist:
                raise NotFoundError("The requested certificate (serial number: {0}) was not found.", serial_number)
            else:
                return None

        # try to load the certificate
        with open(cert_path, "rb") as f:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())

        # check sanity
        if cert.get_serial_number() != serial_number:
            raise RuntimeError("Unexpected certificate serial number.")

        return cert


    # -------------------------------------------------------------------------------------------------------------------------------------


    __revoke_reason_map = {
        "unspecified"            : x509.ReasonFlags.unspecified,
        "key_compromise"         : x509.ReasonFlags.key_compromise,
        "ca_compromise"          : x509.ReasonFlags.ca_compromise,
        "affiliation_changed"    : x509.ReasonFlags.affiliation_changed,
        "superseded"             : x509.ReasonFlags.superseded,
        "cessation_of_operation" : x509.ReasonFlags.cessation_of_operation,
        "certificate_hold"       : x509.ReasonFlags.certificate_hold,
        "privilege_withdrawn"    : x509.ReasonFlags.privilege_withdrawn,
        "aa_compromise"          : x509.ReasonFlags.aa_compromise,
    }


    def revoke_certificate(self, serial_number, reason = "unspecified"):
        """
        Revokes the specified certificate.

        Args:
            serial_number (int) : Serial number of the certificate to revoke
            reason (str)        : Reason of the revocation. May be one of the following:
                                  - 'unspecified'
                                  - 'key_compromise'
                                  - 'ca_compromise'
                                  - 'affiliation_changed'
                                  - 'superseded'
                                  - 'cessation_of_operation'
                                  - 'certificate_hold'
                                  - 'privilege_withdrawn'
                                  - 'aa_compromise'

        Exceptions:
            NotFoundError, if the specified certificate does not exist.

        """

        serial_number = int(serial_number)
        revoke_reason = CertificateAuthority.__revoke_reason_map[reason]

        # get the certificate with the specified serial number
        cert = self.get_certificate(serial_number, raiseIfNotExist = True)

        # get the key and the certificate of the CA
        ca_key = self.key
        ca_cert = self.cert

        # load the old CRL
        with open(self.__ca_crl_path, "rb") as f:
            old_crl = x509.load_pem_x509_crl(f.read(), default_backend())

        # create new CRL and add the revoked certificate to it (the CRL does not expire - or at least nearly 'never' (10 years))
        # (however... strongswan needs to be restarted to reread the CRL!)
        ski = ca_cert.to_cryptography().extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        new_crl = x509.CertificateRevocationListBuilder()
        new_crl = new_crl.issuer_name(old_crl.issuer) \
                         .last_update(datetime.today()) \
                         .next_update(datetime.today() + timedelta(10*365,0,0)) \
                         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), False)
        for revoked_cert in old_crl: new_crl = new_crl.add_revoked_certificate(revoked_cert)
        new_crl = new_crl.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(serial_number) \
                                                                                  .revocation_date(datetime.today()) \
                                                                                  .add_extension(x509.CRLReason(revoke_reason), False) \
                                                                                  .build(default_backend())) \
                         .sign(private_key=ca_key.to_cryptography_key(), algorithm=hashes.SHA256(), backend=default_backend())

        # write the new CRL into a temporary file
        temp_path = self.__ca_crl_path + ".tmp"
        with open(temp_path, "wb+") as f:
            f.write(new_crl.public_bytes(Encoding.PEM))

        # rename the temporary CRL file to the final file
        os.replace(temp_path, self.__ca_crl_path)

    # -------------------------------------------------------------------------------------------------------------------------------------


    def unrevoke_certificate(self, serial_number):
        """
        Unrevokes the specified certificate.

        Args:
            serial_number (int) : Serial number of the certificate to revoke

        Exceptions:
            NotFoundError, if the specified certificate does not exist.

        """

        serial_number = int(serial_number)

        # get the certificate with the specified serial number
        cert = self.get_certificate(serial_number, raiseIfNotExist = True)

        # get the key and the certificate of the CA
        ca_key = self.key
        ca_cert = self.cert

        # load the old CRL
        with open(self.__ca_crl_path, "rb") as f:
            old_crl = x509.load_pem_x509_crl(f.read(), default_backend())

        # create new CRL
        ski = ca_cert.to_cryptography().extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        new_crl = x509.CertificateRevocationListBuilder()
        new_crl = new_crl.issuer_name(old_crl.issuer) \
                         .last_update(datetime.today()) \
                         .next_update(datetime.today() + timedelta(30,0,0)) \
                         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), False)

        # copy all revoked certificates except the one to remove into the new CRL
        removed = False
        for revoked_cert in old_crl:
            if revoked_cert.serial_number == serial_number:
                removed = True
                continue
            new_crl = new_crl.add_revoked_certificate(revoked_cert)

        # sign the new CRL
        new_crl = new_crl.sign(private_key=ca_key.to_cryptography_key(), algorithm=hashes.SHA256(), backend=default_backend())

        # write the new CRL into a temporary file
        temp_path = self.__ca_crl_path + ".tmp"
        with open(temp_path, "wb+") as f:
            f.write(new_crl.public_bytes(Encoding.PEM))

        # rename the temporary CRL file to the final file
        os.replace(temp_path, self.__ca_crl_path)


    # -------------------------------------------------------------------------------------------------------------------------------------


    def add_vpn_client(self, identity):
        """
        Creates a new key/certificate for a VPN client that should be able to connect to the VPN server.

        Args:
            identity (str) : Identity of the client (must be an e-mail address).

        Returns:
            A tuple containing the following data:
            - The serial number of the certificate (int)
            - The client's private key (OpenSSL PKey object)
            - The client's certificate key (OpenSSL X509 object)

        """

        # load the CA's private key and certificate
        # -----------------------------------------------------------------------------------------
        ca_key = self.key
        ca_cert = self.cert

        # retrieve key type to use
        # -----------------------------------------------------------------------------------------
        key_type_name = self.config["client"]["default-key-type"]
        key_type = KeyTypes.get_by_name(key_type_name)
        if key_type == None:
            raise RuntimeError("The configured key type ({0}) is not supported.".format(key_type_name))

        # ensure the the identity is an e-mail address
        # -----------------------------------------------------------------------------------------
        if not is_email_address(identity):
            raise RuntimeError("The specified identity ({0}) is not an e-mail address.".format(identity))

        # create directory where generated certificates are stored, if necessary
        # -----------------------------------------------------------------------------------------
        os.makedirs(self.__storage_dir, exist_ok = True)

        # create the client key
        # ---------------------------------------------------------------------
        client_key = key_type.create_key()

        # create the client certificate
        # ---------------------------------------------------------------------
        client_cert = crypto.X509()
        client_cert.get_subject().C  = "DE"
        client_cert.get_subject().ST = "Berlin"
        client_cert.get_subject().L  = "Berlin"
        client_cert.get_subject().O  = "CloudyCube"
        client_cert.get_subject().OU = "VPN Clients"
        client_cert.get_subject().CN = identity
        client_cert.set_serial_number(self.get_next_serial_number())
        client_cert.gmtime_adj_notBefore(0)
        client_cert.gmtime_adj_notAfter(2*365*24*60*60)
        client_cert.set_issuer(ca_cert.get_subject())
        client_cert.set_pubkey(client_key)
        client_cert.add_extensions(
        [
            # basicConstraints
            # -------------------------------------------------------------------------------------
            crypto.X509Extension(b'basicConstraints', False, b'CA:FALSE'),

            # keyUsage
            # -------------------------------------------------------------------------------------
            crypto.X509Extension(b'keyUsage', False, b'digitalSignature, nonRepudiation, keyEncipherment, keyAgreement'),

            # subjectAltName
            # -------------------------------------------------------------------------------------
            crypto.X509Extension(b"subjectAltName", False, ("email:" + identity).encode()),

            # extendedKeyUsage
            # -------------------------------------------------------------------------------------
            # ikeIntermediate (1.3.6.1.5.5.8.2.2) is required OS X 10.7.3 or older
            # -------------------------------------------------------------------------------------
            crypto.X509Extension(b'extendedKeyUsage', False, b'clientAuth, 1.3.6.1.5.5.8.2.2'),

            # subjectKeyIdentifier and authorityKeyIdentifier
            # -------------------------------------------------------------------------------------
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject = client_cert),
            crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer = ca_cert),
        ])

        client_cert.sign(ca_key, "sha256")

        # write the client's certificate to the storage directory
        # (private key is not needed for further operations)
        # ---------------------------------------------------------------------
        base_filename = "{0:010}".format(client_cert.get_serial_number())
        client_cert_path = os.path.join(self.__storage_dir, base_filename + ".crt")

        try:

            # certificate
            with open(client_cert_path, "wb") as f:
               f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert))
            os.chown(client_cert_path, 0, 0)
            os.chmod(client_cert_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

        except:

            # writing files failed => delete generated files
            if os.path.exists(client_cert_path): os.remove(client_cert_path)
            raise

        return (client_cert.get_serial_number(), client_key, client_cert)


    # -------------------------------------------------------------------------------------------------------------------------------------


    def is_vpn_client_certificate(self, cert):
        """
        Checks whether the specified X509 certificate is a client certificate for the VPN server.

        Args:
            cert (OpenSSL X509 object) : Certificate to check.

        Returns:
            True, if the specified certificate is a client certificate;
            otherwise False

        """

        if not isinstance(cert, crypto.X509):
            raise RuntimeError("The specified argument is not an OpenSSL X509 object.")

        identity = cert.get_subject().CN
        if not is_email_address(identity):
            return False

        # check whether the 'extendedKeyUsage' extension exists and indicates that this is a client certificate
        foundExpectedUsage = False
        for cert_extension_index in range(0, cert.get_extension_count()):
            extension = cert.get_extension(cert_extension_index)
            if extension.get_short_name() == b'extendedKeyUsage':
                cert_usages = [ usage.strip() for usage in str(extension).split(",") ]
                if "TLS Web Client Authentication" in cert_usages:
                    foundExpectedUsage = True
                    break

        if not foundExpectedUsage:
            return False

        return True


    # -------------------------------------------------------------------------------------------------------------------------------------


    def get_vpn_client_certificates(self, include_expired = True, include_revoked = True):
        """
        Gets a list of client certificates the CA has generated for VPN clients.

        Args:
            include_expired (bool) : True to return expired certificates as well; otherwise False.
            include_revoked (bool) : True to return revoked certificates as well; otherwise False.

        Returns:
            A list of OpenSSL X509 objects.

        """

        # get the CA's CRL (checks whether the CA environment is initialized)
        # ---------------------------------------------------------------------
        crl = self.crl

        # scan storage directory for client certificates
        # ---------------------------------------------------------------------
        client_certs = []
        files = [f for f in iglob(self.__storage_dir + "/*.crt", recursive=False) if os.path.isfile(f)]
        for cert_path in files:

            # load certificate
            with open(cert_path, "rb") as f: cert = f.read()
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

            # skip, if the certificate isn't a client certificate
            if not self.is_vpn_client_certificate(cert):
                continue

            # skip, if the certificate has expired (if requested)
            if cert.has_expired() and not show_expired:
                continue

            # check whether the certificate has been revoked
            revoked = crl.get_revoked()
            cert_revoked = False
            if revoked:
                for x in revoked:
                    if cert.get_serial_number() == int(x.get_serial(), 16):
                        cert_revoked = True
                        break
            if cert_revoked and not include_revoked:
                continue

            client_certs.append(cert)

        return client_certs

 
    # -------------------------------------------------------------------------------------------------------------------------------------


    def create_vpn_server_certificate(self, vpn_hostnames, server_key = None):
        """
        Creates a certificate for the VPN server listening to the specified hostnames.
        A key is created as well, if it is not specified explicitly.

        Args:
            vpn_hostnames (list)             : Hostnames and IP addresses the VPN server will be reachable via.
                                               Please prefix hostnames with 'DNS:' and IP addresses with 'IP:'
                                               The first hostname/IP address in the list is put into the Common Name(CN) of the certificate.
                                               All hostnames/IP addresses are put into the X.509 'subjectAltName' extension.
            server_key (OpenSSL PKey object) : The key of the Server to create the certificate with (None to create a new key)

        Returns:
            A tuple containing the key (OpenSSL PKey object) and the certificate (OpenSSL X509 object) of the VPN server.

        """

        # load the CA's private key and certificate (checks whether the CA environment is initialized)
        # -----------------------------------------------------------------------------------------
        ca_key = self.key
        ca_cert = self.cert

        # retrieve key type to use
        # -----------------------------------------------------------------------------------------
        key_type_name = self.config["server"]["default-key-type"]
        key_type = KeyTypes.get_by_name(key_type_name)
        if key_type == None:
            raise RuntimeError("The configured key type ({0}) is not supported.".format(key_type_name))

        # create directory where the key/certificate is stored, if necessary
        # ---------------------------------------------------------------------
        os.makedirs(self.__storage_dir, exist_ok = True)

        # create the private key of the server
        # ---------------------------------------------------------------------
        if server_key == None:
            server_key = key_type.create_key()

        # create the certificate of the server
        # ---------------------------------------------------------------------
        server_cert = crypto.X509()
        server_cert.get_subject().C  = "DE"
        server_cert.get_subject().ST = "Berlin"
        server_cert.get_subject().L  = "Berlin"
        server_cert.get_subject().O  = "CloudyCube"
        server_cert.get_subject().OU = "VPN Provider"
        server_cert.get_subject().CN = ":".join(vpn_hostnames[0].split(":")[1:]) # strips the "DNS:" or "IP:" prefixes
        server_cert.set_serial_number(self.get_next_serial_number())
        server_cert.gmtime_adj_notBefore(0)
        server_cert.gmtime_adj_notAfter(2*365*24*60*60)
        server_cert.set_issuer(ca_cert.get_subject())
        server_cert.set_pubkey(server_key)
        server_cert.add_extensions(
        [
            # basicConstraints
            # -------------------------------------------------------------------------------------
            crypto.X509Extension(b'basicConstraints', False, b'CA:FALSE'),

            # keyUsage
            # -------------------------------------------------------------------------------------
            crypto.X509Extension(b'keyUsage', False, b'digitalSignature, nonRepudiation, keyEncipherment, keyAgreement'),

            # subjectAltName
            # -------------------------------------------------------------------------------------
            crypto.X509Extension(b"subjectAltName", False, ", ".join(vpn_hostnames).encode()),

            # extendedKeyUsage
            # -------------------------------------------------------------------------------------
            # serverAuth (1.3.6.1.5.5.7.3.1) is required by the built-in Windows 7 VPN client
            # ikeIntermediate (1.3.6.1.5.5.8.2.2) is required OS X 10.7.3 or older
            # -------------------------------------------------------------------------------------
            crypto.X509Extension(b'extendedKeyUsage', False, b'serverAuth, 1.3.6.1.5.5.8.2.2'),

            # subjectKeyIdentifier and authorityKeyIdentifier
            # -------------------------------------------------------------------------------------
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject = server_cert),
            crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer = ca_cert),
        ])
        server_cert.sign(ca_key, "sha256")

        # write certificate file
        base_filename = "{0:010}".format(server_cert.get_serial_number())
        server_cert_path = os.path.join(self.__storage_dir, base_filename + ".crt")
        with open(server_cert_path, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert))
        os.chown(server_cert_path, 0, 0)
        os.chmod(server_cert_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

        return (server_key, server_cert)


    # ---------------------------------------------------------------------------------------------------------------------------------------------------------
    # Helper Functions
    # ---------------------------------------------------------------------------------------------------------------------------------------------------------

    def get_next_serial_number(self):
        """
        Gets the serial number for the next certificate and increments the counter.

        Returns:
            The serial number to assign to the next created certificate (int).

        """
        if os.path.exists(self.__ca_next_cert_serial_path):
            with open(self.__ca_next_cert_serial_path, "rt+") as f:
                buf = f.read()
                f.seek(0)
                f.truncate()
                next = int(buf)
                f.write(str(next+1))
                return next
        else:
            next = 0
            with open(self.__ca_next_cert_serial_path, "wt+") as f:
                f.write("{0}".format(next+1))
            return next




# -------------------------------------------------------------------------------------------------------------------------------------------------------------
