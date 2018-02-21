"""
This module contains everything related to the internal certificate authority of the VPN server.
Author: Sascha Falk <sascha@falk-online.eu>
License: MIT License
"""

import configparser
import os
import re
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, BestAvailableEncryption, NoEncryption, load_pem_private_key
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from glob import iglob
from ipaddress import ip_address
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
        return key


class KeyTypes:

    rsa2048   = KeyType("rsa2048", "RSA, 2048 bit",                                                             lambda: rsa.generate_private_key(65537, 2048, default_backend()))
    rsa3072   = KeyType("rsa3072", "RSA, 3072 bit",                                                             lambda: rsa.generate_private_key(65537, 3072, default_backend()))
    rsa4096   = KeyType("rsa4096", "RSA, 4096 bit",                                                             lambda: rsa.generate_private_key(65537, 4096, default_backend()))
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
                if password: ca_key = load_pem_private_key(f.read(), password.encode("utf-8"), default_backend())
                else:        ca_key = load_pem_private_key(f.read(), None, default_backend())
        except ValueError:
            raise InvalidPasswordError("Decrypting CA private key failed. Wrong password.")
        except TypeError:
            if password: raise InvalidPasswordError("Password was specified, but the CA private key is not encrypted.")
            else:        raise InvalidPasswordError("The CA private key is encrypted, but password was not specified.")

        self.__ca_password = password


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
                ca_key = load_pem_private_key(f.read(), None, backend=default_backend())

        except TypeError:

            # private key is encrypted
            return True

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
            return x509.load_pem_x509_certificate(f.read(), default_backend())


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
            NotInitializedError   : The CA environment is not initialized.
            PasswordRequiredError : The key is encrypted, but no password is specified.

        """

        # ensure that the CA environment is initialized
        if not self.is_inited():
            raise NotInitializedError("The CA is not initialized.")

        # ensure that the CA environment is initialized and the password is set, if necessary
        if self.password_required and not self.__ca_password:
            raise PasswordRequiredError("The requested operation requires the CA password to access the private key.")

        # try to decrypt the private key of the CA with the password
        with open(self.__ca_key_path, "rb") as f:
            if self.__ca_password: return load_pem_private_key(f.read(), self.__ca_password.encode("utf-8"), default_backend())
            else:                  return load_pem_private_key(f.read(), None, default_backend())


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
            return x509.load_pem_x509_crl(f.read(), default_backend())


    # -------------------------------------------------------------------------------------------------------------------------------------


    @property
    def crl_path(self):
        """
        Gets the path of the CRL of the CA.

        """
        return self.__ca_crl_path


    # -------------------------------------------------------------------------------------------------------------------------------------


    def init(self, password, ca_key_type, server_key_type, client_key_type, ca_subject_dn, server_subject_dn, client_subject_dn):
        """
        Initialized the CA environment generating related data (private key, certificate and filesystem structure).

        Args:
            password (str)          : Password to protect CA related data with (None, if you don't want to use any protection)
            ca_key_type (str)       : Type of the private key to create for the CA. See class 'KeyType' for supported key types.
            server_key_type (str)   : Type of the private key to create for the server lateron. See class 'KeyType' for supported key types.
            client_key_type (str)   : Type of the private key to use for clients created lateron. See class 'KeyType' for supported key types.
            ca_subject_dn (str)     : Subject name to put into the X.509 certificate of the CA (Distinguished name, DN).
            server_subject_dn (str) : Subject name to put into the X.509 certificate of the VPN server (Distinguished name, DN).
                                      The 'CN' attribute will be overwritten using the VPN server's primary host name.
            client_subject_dn (str) : Subject name to put into the X.509 certificate of VPN clients (Distinguished name, DN).
                                      The 'CN' attribute will be overwritten using the VPN client's identity.

        Exceptions:
            AlreadyInitializedError : The CA is already initialized (associated files are already present).
            ArgumentError           : One of the arguments is invalid.

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

        # ensure that the specified subject DNs are valid
        # ---------------------------------------------------------------------
        try:
            ca_subject = CertificateAuthority.build_x509_name(ca_subject_dn)
        except:
            raise ArgumentError("Invalid subject DN ({0})".format(ca_subject_dn))

        try:
            server_subject = CertificateAuthority.build_x509_name(server_subject_dn)
        except:
            raise ArgumentError("Invalid subject DN ({0})".format(server_subject_dn))

        try:
            client_subject = CertificateAuthority.build_x509_name(client_subject_dn)
        except:
            raise ArgumentError("Invalid subject DN ({0})".format(client_subject_dn))

        # create the CA's private key
        # ---------------------------------------------------------------------
        ca_key = KeyTypes.get_by_name(ca_key_type).create_key()

        # create the CA's certificate
        # ---------------------------------------------------------------------
        ten_years = timedelta(10*365, 0, 0)
        public_key = ca_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(ca_subject)
        builder = builder.issuer_name(ca_subject)  # self-signed
        builder = builder.serial_number(self.get_next_serial_number())
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + ten_years)
        builder = builder.public_key(public_key)
        builder = builder.add_extension(x509.BasicConstraints(True, 0), critical = True)
        builder = builder.add_extension(x509.KeyUsage(digital_signature = False,
                                                      content_commitment = False,
                                                      key_encipherment = False,
                                                      data_encipherment = False,
                                                      key_agreement = False,
                                                      key_cert_sign = True,
                                                      crl_sign = True,
                                                      encipher_only = False,
                                                      decipher_only = False),
                                        critical = True)
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical = False)
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical = False)
        ca_cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend())

        # create the CRL
        # ---------------------------------------------------------------------
        ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(ca_subject)
        builder = builder.last_update(datetime.utcnow())
        builder = builder.next_update(datetime.utcnow() + ten_years)
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), False)
        ca_crl  = builder.sign(private_key = ca_key, algorithm=hashes.SHA256(), backend=default_backend())

        # write everything to disk
        # ---------------------------------------------------------------------
        try:

            # private key
            with open(self.__ca_key_path, "wb") as f:
                if password:
                    f.write(ca_key.private_bytes(
                        encoding = Encoding.PEM,
                        format = PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm = BestAvailableEncryption(password.encode("utf-8"))))
                else:
                    f.write(ca_key.private_bytes(
                        encoding = Encoding.PEM,
                        format = PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm = NoEncryption()))
            os.chown(self.__ca_key_path, 0, 0)
            os.chmod(self.__ca_key_path, S_IRUSR | S_IWUSR)

            # certificate
            with open(self.__ca_cert_path, "wb") as f:
               f.write(ca_cert.public_bytes(Encoding.PEM))
            os.chown(self.__ca_cert_path, 0, 0)
            os.chmod(self.__ca_cert_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

            # CRL
            with open(self.__ca_crl_path, "wb") as f:
                f.write(ca_crl.public_bytes(Encoding.PEM))
            os.chown(self.__ca_cert_path, 0, 0)
            os.chmod(self.__ca_cert_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

            # configuration
            config = configparser.ConfigParser()
            config["server"] = {}
            config["server"]["default-key-type"] = server_key_type.lower()
            config["server"]["subject"] = server_subject_dn
            config["client"] = {}
            config["client"]["default-key-type"] = client_key_type.lower()
            config["client"]["subject"] = client_subject_dn
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
            A certificate object;
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
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        # check sanity
        if cert.serial_number != serial_number:
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
        ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        new_crl = x509.CertificateRevocationListBuilder()
        new_crl = new_crl.issuer_name(old_crl.issuer)
        new_crl = new_crl.last_update(datetime.utcnow())
        new_crl = new_crl.next_update(datetime.utcnow() + timedelta(10*365,0,0))
        new_crl = new_crl.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), False)
        for revoked_cert in old_crl: new_crl = new_crl.add_revoked_certificate(revoked_cert)
        revoked_cert = x509.RevokedCertificateBuilder()
        revoked_cert = revoked_cert.serial_number(serial_number)
        revoked_cert = revoked_cert.revocation_date(datetime.utcnow())
        revoked_cert = revoked_cert.add_extension(x509.CRLReason(revoke_reason), False)
        revoked_cert = revoked_cert.build(default_backend())
        new_crl = new_crl.add_revoked_certificate(revoked_cert)
        new_crl = new_crl.sign(private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend())

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
        ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        new_crl = x509.CertificateRevocationListBuilder()
        new_crl = new_crl.issuer_name(old_crl.issuer)
        new_crl = new_crl.last_update(datetime.utcnow())
        new_crl = new_crl.next_update(datetime.utcnow() + timedelta(10*365,0,0))
        new_crl = new_crl.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), False)

        # copy all revoked certificates except the one to remove into the new CRL
        removed = False
        for revoked_cert in old_crl:
            if revoked_cert.serial_number == serial_number:
                removed = True
                continue
            new_crl = new_crl.add_revoked_certificate(revoked_cert)

        # sign the new CRL
        new_crl = new_crl.sign(private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend())

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
            - The client's private key (a cryptography key object, exact type depends on the configured key type)
            - The client's certificate key (cryptography.x509.Certificate)

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
            raise ValueError("The configured key type ({0}) is not supported.".format(key_type_name))

        # ensure the the identity is an e-mail address
        # -----------------------------------------------------------------------------------------
        if not is_email_address(identity):
            raise ValueError("The specified identity ({0}) is not an e-mail address.".format(identity))

        # build subject DN for the certificate
        # -----------------------------------------------------------------------------------------
        subject = CertificateAuthority.build_x509_name(self.config["server"]["subject"])
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, identity),
            *list(CertificateAuthority.filter(lambda x: x.oid != NameOID.COMMON_NAME, subject))
        ])

        # create directory where generated certificates are stored, if necessary
        # -----------------------------------------------------------------------------------------
        os.makedirs(self.__storage_dir, exist_ok = True)

        # create the client key
        # ---------------------------------------------------------------------
        client_key = key_type.create_key()

        # create the client certificate
        # ---------------------------------------------------------------------
        public_key = client_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(ca_cert.issuer)
        builder = builder.serial_number(self.get_next_serial_number())
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + timedelta(2*365, 0, 0))
        builder = builder.public_key(public_key)
        builder = builder.add_extension(x509.BasicConstraints(False, None), critical = True)
        builder = builder.add_extension(x509.KeyUsage(digital_signature  = True,
                                                      content_commitment = True,  # non repudiation
                                                      key_encipherment   = True,
                                                      data_encipherment  = False,
                                                      key_agreement      = True,
                                                      key_cert_sign      = False,
                                                      crl_sign           = False,
                                                      encipher_only      = False,
                                                      decipher_only      = False),
                                        critical = True)
        builder = builder.add_extension(x509.SubjectAlternativeName([ x509.RFC822Name(identity) ]), critical=False)
        builder = builder.add_extension(x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            x509.ObjectIdentifier("1.3.6.1.5.5.8.2.2")    # ikeIntermediate (1.3.6.1.5.5.8.2.2) is required OS X 10.7.3 or older
        ]), critical=False)
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
        client_cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend())

        # write the client's certificate to the storage directory
        # (private key is not needed for further operations)
        # ---------------------------------------------------------------------
        base_filename = "{0:010}".format(client_cert.serial_number)
        client_cert_path = os.path.join(self.__storage_dir, base_filename + ".crt")

        try:

            # certificate
            with open(client_cert_path, "wb") as f:
                f.write(client_cert.public_bytes(Encoding.PEM))
            os.chown(client_cert_path, 0, 0)
            os.chmod(client_cert_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

        except:

            # writing files failed => delete generated files
            if os.path.exists(client_cert_path): os.remove(client_cert_path)
            raise

        return (client_cert.serial_number, client_key, client_cert)


    # -------------------------------------------------------------------------------------------------------------------------------------


    def is_vpn_client_certificate(self, cert):
        """
        Checks whether the specified X509 certificate is a client certificate for the VPN server.

        Args:
            cert (cryptography.x509.Certificate) : Certificate to check.

        Returns:
            True, if the specified certificate is a client certificate;
            otherwise False

        """

        if not isinstance(cert, x509.Certificate):
            raise TypeError("The specified argument is not a x509 certificate object.")

        # check whether the common name (CN) of the subject is an e-mail address
        cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(cns) != 1: return False
        if not is_email_address(cns[0].value):
            return False

        # check whether the 'Extended Key Usage' extension exists and indicates that this is a client certificate
        foundExpectedUsage = False
        for extension in cert.extensions:
            if extension.oid == x509.ExtendedKeyUsage.oid:
                if x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in extension.value:
                    foundExpectedUsage = True
                    break
        if not foundExpectedUsage:
            return False

        return True


    # -------------------------------------------------------------------------------------------------------------------------------------


    def get_vpn_client_certificates(self, identity = None, include_expired = True, include_revoked = True):
        """
        Gets a list of client certificates the CA has generated for VPN clients.

        Args:
            identity (str)         : Identity of the client whose certificates are to get (None to get certificates of all users).
            include_expired (bool) : True to return expired certificates as well; otherwise False.
            include_revoked (bool) : True to return revoked certificates as well; otherwise False.

        Returns:
            A list of cryptography.x509.Certificate objects.

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
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read(), default_backend())

            # skip, if the certificate isn't a client certificate
            if not self.is_vpn_client_certificate(cert):
                continue

            # skip, if the identity is not the requested one
            if identity:
                cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if len(cns) != 1: continue
                if cns[0].value.lower() != identity.lower(): continue

            # skip, if the certificate has expired (if requested)
            if datetime.utcnow() > cert.not_valid_after and not include_expired:
                continue

            # check whether the certificate has been revoked
            cert_revoked = False
            for revocation in crl:
                if cert.serial_number == revocation.serial_number:
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
            vpn_hostnames (list)                 : Hostnames and IP addresses the VPN server will be reachable via.
                                                   Please prefix hostnames with 'DNS:' and IP addresses with 'IP:'
                                                   The first hostname/IP address in the list is put into the Common Name(CN) of the certificate.
                                                   All hostnames/IP addresses are put into the X.509 'subjectAltName' extension.
            server_key (cryptography key object) : The key of the Server to create the certificate with (None to create a new key)

        Returns:
            A tuple containing the key (cryptography key object) and the certificate (cryptography.x509.Certificate object) of the VPN server.

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
            raise ValueError("The configured key type ({0}) is not supported.".format(key_type_name))

        # build subject DN for the certificate
        # -----------------------------------------------------------------------------------------
        subject = CertificateAuthority.build_x509_name(self.config["server"]["subject"])
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, vpn_hostnames[0].split(":", 1)[1]),
            *list(CertificateAuthority.filter(lambda x: x.oid != NameOID.COMMON_NAME, subject))
        ])

        # create directory where the key/certificate is stored, if necessary
        # ---------------------------------------------------------------------
        os.makedirs(self.__storage_dir, exist_ok = True)

        # create the private key of the server
        # ---------------------------------------------------------------------
        if server_key == None:
            server_key = key_type.create_key()

        # create the certificate of the server
        # ---------------------------------------------------------------------
        public_key = server_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(ca_cert.issuer)
        builder = builder.serial_number(self.get_next_serial_number())
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + timedelta(2*365, 0, 0))
        builder = builder.public_key(public_key)
        builder = builder.add_extension(x509.BasicConstraints(False, None), critical = True)
        builder = builder.add_extension(x509.KeyUsage(digital_signature  = True,
                                                      content_commitment = True,  # non repudiation
                                                      key_encipherment   = True,
                                                      data_encipherment  = False,
                                                      key_agreement      = True,
                                                      key_cert_sign      = False,
                                                      crl_sign           = False,
                                                      encipher_only      = False,
                                                      decipher_only      = False),
                                        critical = True)


        # add 'Subject Alternative Name' extension
        builder = builder.add_extension(CertificateAuthority.build_san(vpn_hostnames), critical=False)

        # add 'Extended Key Usage' extension
        builder = builder.add_extension(x509.ExtendedKeyUsage([
                                            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                                            x509.ObjectIdentifier("1.3.6.1.5.5.8.2.2")    # ikeIntermediate (1.3.6.1.5.5.8.2.2) is required OS X 10.7.3 or older
                                        ]), critical=False)

        # add 'Subject Key Identifier' extension
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)

        # add 'Authority Key Identifier' extension
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)

        # sign the certificate
        server_cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend())

        # write certificate file
        base_filename = "{0:010}".format(server_cert.serial_number)
        server_cert_path = os.path.join(self.__storage_dir, base_filename + ".crt")
        with open(server_cert_path, "wb") as f:
            f.write(server_cert.public_bytes(Encoding.PEM))
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
            next = 1
            with open(self.__ca_next_cert_serial_path, "wt+") as f:
                f.write("{0}".format(next+1))
            return next

    @classmethod
    def filter(cls, pred, items):
        """
        A generator applying a predicate to filter elements.
        """
        for elem in items:
            if pred(elem):
                yield elem


    @classmethod
    def build_x509_name(cls, dn):
        """
        Builds a X.509 name (as used by the cryptography module) from a distinguished name (DN).

        Args:
            dn (str) : DN to create the X.509 name from.

        Returns:
            The X.509 name corresponding to the specified DN.

        """
        name_attributes = []
        for part in CertificateAuthority.split_dn(dn):
            type = part[0].upper()
            if   type == "CN":              name_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, part[1]))
            elif type == "C":               name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, part[1]))
            elif type == "L":               name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, part[1]))
            elif type == "O":               name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, part[1]))
            elif type == "OU":              name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, part[1]))
            elif type == "ST":              name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, part[1]))
            else: raise ValueError("Unknown attribute type ({0}).".format(part[0]))
        return x509.Name(name_attributes)

    @classmethod
    def split_dn(cls, dn):
        """
        Splits the specified distinguished name (DN) into the attributes it consists of.

        Args:
            dn (str) : DN to split.

        """
        attributes = re.split(r"(?!\\),", dn)                           # split DN into attributes
        attributes = [re.split(r"(?!\\)=", x, 1) for x in attributes]   # split DN attributes into type and value
        attributes = [[y.strip() for y in x] for x in attributes]       # trim whitespaces at start and end of attribute types/values
        dn_ok = all([len(x) == 2 for x in attributes])
        if not dn_ok: raise ValueError("The specified DN is not valid.")
        return attributes


    @classmethod
    def build_san(cls, hostnames):
        subjectAlternativeNames = []
        for name in hostnames:
            tokens = name.split(":", 1)
            if len(tokens) < 2: raise ValueError("Missing 'DNS:' before hostname or 'IP:' befire IP address.")
            type = tokens[0].lower()
            if type == "dns":
                subjectAlternativeNames.append(x509.DNSName(tokens[1]))
            elif type == "ip":
                subjectAlternativeNames.append(x509.IPAddress(ip_address(tokens[1])))
            else:
                raise ValueError("Invalid prefix ({0}:), expecting 'DNS:' before hostname or 'IP:' before IP address.".format(tokens[0]))
        return x509.SubjectAlternativeName(subjectAlternativeNames)




# -------------------------------------------------------------------------------------------------------------------------------------------------------------
