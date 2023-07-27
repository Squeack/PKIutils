#!/usr/bin/env python3

import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.x509 import ocsp
from cryptography.x509 import oid
from cryptography.x509.ocsp import OCSPResponseStatus
import socket
import argparse
import pprint
import requests
from urllib.parse import urljoin
import base64
import os

def x509_fields(x509cert):
    fields = {}
    try:
        fields["subject"] = x509cert.subject
    except AttributeError:
        pass
    try:
        fields["issuer"] = x509cert.issuer
    except AttributeError:
        pass
    try:
        fields["version"] = x509cert.version
    except AttributeError:
        pass
    try:
        fields["serial_number"] = x509cert.serial_number
    except AttributeError:
        fields["serial_number"] = None
    try:
        fields["public_key"] = x509cert.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    except AttributeError:
        pass
    try:
        fields["not_valid_before"] = x509cert.not_valid_before
    except AttributeError:
        pass
    try:
        fields["not_valid_after"] = x509cert.not_valid_after
    except AttributeError:
        pass
    try:
        fields["signature_algorithm_oid"] = x509cert.signature_algorithm_oid
    except AttributeError:
        pass
    try:
        for ext in x509cert.extensions:
            fields["extension:{}".format(ext.oid._name)] = ext.value
    except AttributeError:
        pass
    return fields


def x509_key_usage(ku):
    uses = []
    if ku.digital_signature: uses.append("Digital signature")
    if ku.content_commitment: uses.append("Content commitment")
    if ku.key_encipherment: uses.append("Key encipherment")
    if ku.data_encipherment: uses.append("Data encipherment")
    if ku.key_agreement:
        uses.append("Key agreement")
        if ku.encipher_only: uses.append("Encipher only")
        if ku.decipher_only: uses.append("Decpiher only")
    if ku.key_cert_sign: uses.append("Key cert signing")
    if ku.crl_sign: uses.append("CRL sign")
    return uses


def x509_ext_key_usage(eku):
    uses = []
    for extuse in eku:
        uses.append(extuse._name)
    return uses


def x509_crl(cert):
    try:
        crldps = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    except x509.extensions.ExtensionNotFound as e:
        return []
    crl = []
    for dp in crldps:
        dpnames = dp.full_name
        for dpname in dpnames:
            crl.append(dpname.value)
    return crl


def x509_aia(cert):
    try:
        aias = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.extensions.ExtensionNotFound as e:
        return {}
    ads = {}
    for ad in aias:
        ads[ad.access_method._name] = ad.access_location.value
    return ads


def download_x509_from_url(certurl, usecache=False):
    #print("Downloading {}".format(certurl))
    fullname=certurl.split("://")[1]
    pieces=fullname.split("/")
    fpath = "/".join(pieces[0:-1])
    fname = pieces[-1]
    certtype = fname.split(".")[-1].lower()
    cert = requests.get(certurl)
    if not cert.ok:
        return None
    if usecache:
        os.makedirs(fpath, exist_ok=True)
        with open(fullname, "wb") as file:
            file.write(cert.content)
            file.close()
    x509cert = None
    try:
        x509cert = x509.load_der_x509_certificate(cert.content)
    except:
        #print("Failed to import as DER")
        x509cert = None
        try:
            x509cert = x509.load_pem_x509_certificate(cert.content)
        except:
            #print("Failed to import as PEM")
            x509cert = None
    return x509cert


def download_crl(crlurl, savetocache=False, refreshcache=False):
    fullname=crlurl.split("://")[1]
    if os.path.isfile(fullname) and not refreshcache:
        #print("Using cached CRL")
        with open(fullname, "rb") as file:
            crldata = file.read()
            file.close()
            return crldata
    pieces=fullname.split("/")
    fpath = "/".join(pieces[0:-1])
    fname = pieces[-1]
    #print("Downloading {} into {}".format(fname, fpath))
    crldata = requests.get(crlurl)
    if not crldata.ok:
        return None
    if savetocache:
        os.makedirs(fpath, exist_ok=True)
        with open(fullname, "wb") as file:
            file.write(crldata.content)
            file.close()
    return crldata.content


def validate_ssl_certificate(url, port=443):
    try:
        #print("Validating certificate from port {}".format(port))
        # Create a socket and connect to the server
        sock = socket.create_connection((url, port))
        # Create an SSL context
        context = ssl.create_default_context()
        context.verify_flags = ssl.VERIFY_X509_STRICT
        # Wrap the socket with the SSL context
        with context.wrap_socket(sock, server_hostname=url) as ssl_sock:
            print("SSL Protocol: {}".format(ssl.get_protocol_name(context.protocol)))
            # Get the SSL certificate
            cert = ssl_sock.getpeercert()
            sock.close()
            return True,""
    except ssl.SSLCertVerificationError as e:
        return False, e.verify_message
    except ssl.SSLError as e:
        return False, e.strerror
    except socket.error as e:
        return False, e.strerror
    else:
        if sock is not None:
            #print("Closing socket")
            sock.close()


def get_ocsp_status(x509_cert, hash=SHA1(), savetocache=False, refreshcache=False):
    aia = x509_aia(x509_cert)
    #pretty.pprint(aia)
    if "OCSP" in aia:
        ocsp_server = aia["OCSP"]
        if "caIssuers" in aia:
            issuer = aia["caIssuers"]
            issuercert = download_x509_from_url(issuer, savetocache)
        else:
            return False, "No issuing certificate for OCSP check"
        ocspbuilder = x509.ocsp.OCSPRequestBuilder()
        ocspbuilder = ocspbuilder.add_certificate(x509_cert, issuercert, hash)
        req = ocspbuilder.build()
        req_path = base64.b64encode(req.public_bytes(Encoding.DER))
        request = urljoin(ocsp_server + '/', req_path.decode('ascii'))
        #pretty.pprint(request)
        ocsp_response = requests.get(request)
        if ocsp_response.ok:
            #pretty.pprint(ocsp_response)
            #pretty.pprint(ocsp_response.content)
            ocsp_decoded = ocsp.load_der_ocsp_response(ocsp_response.content)
            #pretty.pprint(ocsp_decoded)
            if ocsp_decoded.response_status == OCSPResponseStatus.SUCCESSFUL:
                #print("OCSP check complete")
                #pretty.pprint(ocsp_decoded)
                return True, ocsp_decoded.certificate_status
            else:
                #print("Failed to decode OCSP response")
                #print(ocsp_decoded.response_status)
                return False, ocsp_decoded.response_status
        else:
            return False, "Failed to get valid OCSP response"
    else:
        return False, "No OCSP server found"


def validate_ocsp_revocation(x509_cert, savetocache=False, refreshcache=False):
    checked, status = get_ocsp_status(x509_cert, hash=SHA1(), savetocache=savetocache, refreshcache=refreshcache)
    if status == ocsp.OCSPResponseStatus.UNAUTHORIZED:
        #print("Using alternative hash algorithm for OCSP")
        checked, status = get_ocsp_status(x509_cert, hash=SHA256(), savetocache=savetocache, refreshcache=refreshcache)
    return checked, status


def validate_crl_revocation(x509_cert, savetocache=False, refreshcache=False):
    sn = x509_cert.serial_number
    #print("Validating certificate revocation for certificate {}".format(sn))
    decode = x509_fields(x509_cert)
    if "extension:cRLDistributionPoints" in decode:
        crldps = x509_crl(x509_cert)
        #print("CRL distribtion points: {}".format(crldps))
        crl = None
        try:
            for crlurl in crldps:
                crldata = download_crl(crlurl, savetocache=savetocache, refreshcache=refreshcache)
                #print("{} bytes downloaded".format(len(crldata)))
                if crldata[:4] == "----":
                    #print("Assuming PEM format")
                    crl = x509.load_pem_x509_crl(crldata)
                else:
                    #print("Assuming DER format")
                    crl = x509.load_der_x509_crl(crldata)
                #print("{} certificates revoked".format(len(crl)))
                return True, crl.get_revoked_certificate_by_serial_number(sn) is not None
        except Exception as e:
            print(e.strerror)
            pass # Try next crl distribution point
    #else:
        #print("No CRL distribution points found")
    #print("Revocation cannot be checked")
    return False, False

def get_ssl_certificate(url, port=443):
    der_cert = None
    pem_cert = None
    x509_cert = None
    try:
        print("Fetching certificate from port {}".format(port))
        # Create a socket and connect to the server
        sock = socket.create_connection((url, port))
        # Create an SSL context
        context = ssl.create_default_context()
        # Turn off certificate validation
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        # Wrap the socket with the SSL context
        with context.wrap_socket(sock, server_hostname=url) as ssl_sock:
            # Get the SSL certificate in binary (DER) format
            der_cert = ssl_sock.getpeercert(True)
            # Convert to PEM format
            pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
            # Extract fields
            #x509_cert = x509.load_pem_x509_certificate(str.encode(pem_cert), default_backend())
            x509_cert = x509.load_pem_x509_certificate(pem_cert.encode('ascii'), default_backend())
            sock.close()
            return der_cert, pem_cert, x509_cert
    except ssl.SSLError as e:
        print("SSLError: {}".format(e))
        return der_cert, pem_cert, x509_cert
    except socket.error as e:
        print("Socket error: {}".format(e))
        return der_cert, pem_cert, x509_cert


def traverse_chain(cert, indent=0, followchain=False, checkrevoke=False, usecache=False, refresh=False, verbose=False):
    nextcert = cert
    anythingrevoked = False
    checkscomplete = True
    while nextcert is not None:
        display_x509_summary(nextcert, indent)
        aia = x509_aia(nextcert)
        if checkrevoke:
            revokedatthislevel = False
            checkedatthislevel = False
            checked, revoked = validate_crl_revocation(nextcert, savetocache=usecache, refreshcache=refresh)
            print("{}Able to check revocation via CRL: {}".format(" "*indent, checked))
            if checked:
                checkedatthislevel = True
                revokedatthislevel |= revoked
                print("{}Revocation checked passed: {}".format(" "*indent, not revoked))
            else:
                print("{}Unable to check CRL".format(" "*indent))
            checked, status = validate_ocsp_revocation(nextcert, savetocache=usecache, refreshcache=refresh)
            if checked:
                checkedatthislevel = True
                revokedatthislevel |= status == ocsp.OCSPCertStatus.REVOKED
                print("{}OCSP status: {}".format(" "*indent, status))
            else:
                print("{}Unable to query OCSP server: {}".format(" "*indent, status))
            anythingrevoked |= revokedatthislevel
            checkscomplete &= checkedatthislevel
        if verbose:
            display_x509_full(nextcert, indent)
        nexturl = None
        if "caIssuers" in aia:
            nexturl = aia["caIssuers"]
        if nexturl is not None and followchain:
            nextcert = download_x509_from_url(nexturl, usecache)
        else:
            nextcert = None
        indent += 4
    if followchain:
        print("{}End of chain".format(" "*indent))
        print("Whole chain checked for revocation: {}".format(checkscomplete))
        print("Anything in chain revoked: {}".format(anythingrevoked))


def display_x509_basic(cert, indent=0):
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after
    print("{}Subject: {} ({} - {})".format(" "*indent, cert.subject.rfc4514_string(), not_before, not_after))
    print("{}AIA: {}".format(" "*indent, x509_aia(cert)))
    print("{}CRL: {}".format(" "*indent, x509_crl(cert)))


def display_x509_summary(cert, indent=0):
    decode = x509_fields(cert)
    subject = decode["subject"].rfc4514_string()
    print("{}Subject: {}".format(" "*indent, subject))
    if "extension:subjectAltName" in decode:
        print("{}SAN: {}".format(" "*indent, decode["extension:subjectAltName"].get_values_for_type(x509.DNSName)))
    issuer = decode["issuer"].rfc4514_string()
    print("{}Issuer: {}".format(" "*indent, issuer))
    if subject == issuer:
        print("{}SELF SIGNED !!! (Expected only for root CA certificates)".format(" "*indent))
    if "serial_number" in decode:
        print("{}Serial number: {}".format(" "*indent, decode["serial_number"]))
    print("{}Version: {}".format(" "*indent, decode["version"]))
    if "extension:keyUsage" in decode:
        print("{}Key usage: {}".format(" "*indent, x509_key_usage(decode["extension:keyUsage"])))
    if "extension:extendedKeyUsage" in decode:
        print("{}Extended key usage: {}".format(" "*indent, x509_ext_key_usage(decode["extension:extendedKeyUsage"])))
    print("{}AIA: {}".format(" "*indent, x509_aia(cert)))
    print("{}CRL: {}".format(" "*indent, x509_crl(cert)))
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after
    print("{}Not valid before: {}".format(" "*indent, not_before))
    print("{}Not valid after: {}".format(" "*indent, not_after))


def display_x509_full(cert, indent=0):
    decode = x509_fields(cert)
    pretty.pprint(decode)


def test_url(url, port=443, followchain=False, checkrevoke=False, usecache=False, refresh=False, verbose=False):
    print(url, port)
    valid, cause = validate_ssl_certificate(url, port)
    print("Certificate valid: {}".format(valid))
    if not valid:
        print("Reason: {}".format(cause))
    der_cert, pem_cert,x509_cert = get_ssl_certificate(url, port)
    if x509_cert is not None:
        traverse_chain(x509_cert, followchain=followchain, checkrevoke=checkrevoke, usecache=usecache, refresh=refresh, verbose=verbose)
    else:
        print("Failed to retrieve SSL certificate chain.")
    print("")


# Entry point for non-library usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", type=str, action="store")
    parser.add_argument("-T", "--targetlist", type=str, action="store")
    parser.add_argument("-c", "--chain", action="store_true")
    parser.add_argument("-r", "--revocation", action="store_true")
    parser.add_argument("--cache", action="store_true")
    parser.add_argument("--refreshcrl", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    urls = []
    if args.target is not None:
        urls.append(args.target)
    if args.targetlist is not None:
        # Load list of URLs from a passed in filename
        # Not yet implemented
        pass
    if args.target is None and args.targetlist is None:
        # Should be okay
        urls.append("www.google.com")
        urls.append("badssl.com")
        # Various deliberate errors
        urls.append("expired.badssl.com")
        urls.append("wrong.host.badssl.com")
        urls.append("self-signed.badssl.com")
        urls.append("untrusted-root.badssl.com")
        # urls.append("revoked.badssl.com") # Has now expired, which takes precedence in the checks
        urls.append("digicert-tls-ecc-p384-root-g5-revoked.chain-demos.digicert.com")
        urls.append("pinning-test.badssl.com")
        urls.append("no-common-name.badssl.com")
        urls.append("no-subject.badssl.com")
        urls.append("incomplete-chain.badssl.com")
        urls.append("dh480.badssl.com")
        urls.append("no-sct.badssl.com")
        urls.append("edellroot.badssl.com")
        urls.append("3des.badssl.com")
        urls.append("doesnotexist.localdomain")
        # Also various non http-based protocols
        urls.append("imap.btinternet.com 993")
        urls.append("pop.btinternet.com 995")
        urls.append("smtp.btinternet.com 465")
    pretty = pprint.PrettyPrinter(indent=2, width=800)
    #pretty.pprint(args)

    for url in urls:
        pieces = url.split(" ")
        if len(pieces) == 1:
          test_url(url, followchain=args.chain, checkrevoke=args.revocation, usecache=args.cache, refresh=args.refreshcrl, verbose=args.verbose)
        else:
          test_url(pieces[0], pieces[1])
