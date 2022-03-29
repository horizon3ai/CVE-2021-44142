"""
This file provides extensions the smbprotocol package
"""
import logging
import threading
from collections import OrderedDict
from typing import Dict

from smbprotocol import MAX_PAYLOAD_SIZE
from smbprotocol.connection import Connection, Request
from smbprotocol.file_info import FileFullEaInformation, QueryInfoFlags, FileBasicInformation, FileAttributes, \
    FileDispositionInformation
from smbprotocol.header import SMB2HeaderResponse
from smbprotocol.open import SMB2QueryInfoRequest, Open, SMB2SetInfoRequest, SMB2SetInfoResponse, SMB2QueryInfoResponse
from smbprotocol.session import Session
from smbprotocol.structure import Structure, BytesField, IntField, FlagField
from smbprotocol.tree import TreeConnect


class SMBFlags(object):
    """
    Flags for the SMB header
    """
    SMB_FLAGS_LOCK_AND_READ_OK = 0x01
    SMB_FLAGS_BUF_AVAIL = 0x02
    RESERVED = 0x04
    SMB_FLAGS_CASE_INSENSITIVE = 0x08
    SMB_FLAGS_CANONICALIZED_PATHS = 0x10
    SMB_FLAGS_OPLOCK = 0x20
    SMB_FLAGS_OPBATCH = 0x40
    SMB_FLAGS_REPLY = 0x80


class SMBFlags2(object):
    """
    Flags2 for the SMB header
    """
    SMB_FLAGS2_LONG_NAMES = 0x0001
    SMB_FLAGS2_EAS = 0x0002
    SMB_FLAGS2_SMB_SECURITY_SIGNATURE = 0x0004
    SMB_FLAGS2_IS_LONG_NAME = 0x0040
    SMB_FLAGS2_EXTENDED_SECURITY = 0x0800
    SMB_FLAGS2_DFS = 0x1000
    SMB_FLAGS2_PAGING_IO = 0x2000
    SMB_FLAGS2_NT_STATUS = 0x4000
    SMB_FLAGS2_UNICODE = 0x8000


class SMBHeader(Structure):
    """
    Structure definition for SMBHeader
    """
    def __init__(self):
        self.fields = OrderedDict([
            ('protocol', BytesField(
                size=4,
                default=b"\xffSMB"
            )),
            ('command', IntField(
                size=1
            )),
            ('status', IntField(size=4)),
            ('flags', FlagField(
                size=1,
                flag_type=SMBFlags,
            )),
            ('flags2', FlagField(
                size=2,
                flag_type=SMBFlags2
            )),
            ('pid_high', IntField(size=2, default=0)),
            ('signature', IntField(size=8, default=0)),
            ('reserved', IntField(size=2, default=0)),
            ('tree_id', IntField(size=2)),
            ('pid_low', IntField(size=2)),
            ('uid', IntField(size=2)),
            ('mid', IntField(size=2))
        ])
        super(SMBHeader, self).__init__()


class SMBNegotiateRequest(Structure):
    """
    Structure definition for SMBNegotiateRequest
    """
    def __init__(self):
        self.fields = OrderedDict([
            ('word_count', IntField(size=1)),
            ('byte_count', IntField(size=2)),
            # ('dialects', BytesField(list_type=TextField()))
        ])
        super(SMBNegotiateRequest, self).__init__()


class OSXConnection(Connection):
    """
    WD My Could OS firmware has a custom patch that disables the vulnerable vfs modules unless
    the connection appears to be from OSX. This means that the first message from the connection is
    an SMB negotitate request with the following dialects set.
    * NT LM 0.12
    * SMB 2.002
    * SMB 2.???
    """
    def __init__(self, *args, **kwargs):
        super(OSXConnection, self).__init__(*args, **kwargs)
        self.disconnect_called = False
        self.send_called = False
    
    def disconnect(self, close=True):
        """
        This is a hack, the message_thread raises an exception because it expects
        an SMB2 message, but it receives an SMB message. So here we restart the
        message thread if it's the first time disconnect is called.
        """
        if self.disconnect_called:
            super(OSXConnection, self).disconnect(close=close)
        else:
            # Receive the response
            t_worker = threading.Thread(target=self._process_message_thread,
                                        name="msg_worker-%s:%s" % (self.server_name, self.port))
            t_worker.daemon = True
            t_worker.start()
            self._t_exc = None
            self.disconnect_called = True

    def _send_smb2_negotiate(self, dialect, timeout, encryption_algorithms, signing_algorithms):
        """
        Override _send_smb2_negotiate to send an SMB Negotiate request to make Samba think the
        request is coming from OSX
        """
        header = SMBHeader()
        header['command'] = 0x72
        header['status'] = 0
        header['flags'] = SMBFlags.SMB_FLAGS_CASE_INSENSITIVE
        header['flags2'] = SMBFlags2.SMB_FLAGS2_UNICODE | \
                           SMBFlags2.SMB_FLAGS2_NT_STATUS | \
                           SMBFlags2.SMB_FLAGS2_EXTENDED_SECURITY | \
                           SMBFlags2.SMB_FLAGS2_LONG_NAMES
        header['tree_id'] = 65535
        header['pid_low'] = 1
        header['uid'] = 65535
        header['mid'] = 0

        b_header = header.pack()

        neg_req = SMBNegotiateRequest()
        neg_req['word_count'] = 0
        neg_req['byte_count'] = 34
        b_neg_req = neg_req.pack()

        # Add the dialects
        b_neg_req += b"\x02" + 'NT LM 0.12'.encode('utf-8') + b"\x00"
        b_neg_req += b"\x02" + 'SMB 2.002'.encode('utf-8') + b"\x00"
        b_neg_req += b"\x02" + 'SMB 2.???'.encode('utf-8') + b"\x00"

        self.transport.send(b_header + b_neg_req)
        self.sequence_window['low'] = 1
        self.sequence_window['high'] = 2
        while not self.disconnect_called and self.transport.connected:
            logging.info("[HACK] waiting for disconnect to occur")
        if not self.transport.connected:
            raise OSError("No connection to server")
        return super()._send_smb2_negotiate(dialect, timeout, encryption_algorithms, signing_algorithms)


def set_extended_attributes(file_open: Open, attribute: bytes, value: bytes) -> SMB2SetInfoResponse:
    """
    Set extended attributes for an Open
    :param file_open: file to set extended attribute
    :param attribute: name of attribute
    :param value: attribute value
    :return: response
    """
    ea_info = FileFullEaInformation()
    ea_info['ea_name'] = attribute
    ea_info['ea_value'] = value
    info_buffer = ea_info
    set_req = SMB2SetInfoRequest()
    set_req['info_type'] = info_buffer.INFO_TYPE
    set_req['file_info_class'] = info_buffer.INFO_CLASS
    set_req['file_id'] = file_open.file_id
    set_req['buffer'] = info_buffer
    tree: TreeConnect = file_open.tree_connect
    session: Session = tree.session
    connection: Connection = session.connection
    request: Request = connection.send(set_req, session.session_id, tree.tree_connect_id)
    response: SMB2HeaderResponse = connection.receive(request)
    set_resp = SMB2SetInfoResponse()
    set_resp.unpack(response['data'].get_value())
    return set_resp


def delete_file(file_open: Open):
    """
    Delete a file
    :param file_open: File to delete
    """
    basic_info = FileBasicInformation()
    basic_info['creation_time'] = 0
    basic_info['last_access_time'] = 0
    basic_info['last_write_time'] = 0
    basic_info['change_time'] = 0
    basic_info['file_attributes'] = FileAttributes.FILE_ATTRIBUTE_NORMAL
    set_req = SMB2SetInfoRequest()
    set_req['info_type'] = basic_info.INFO_TYPE
    set_req['file_info_class'] = basic_info.INFO_CLASS
    set_req['file_id'] = file_open.file_id
    set_req['buffer'] = basic_info
    tree: TreeConnect = file_open.tree_connect
    session: Session = tree.session
    connection: Connection = session.connection
    request: Request = connection.send(set_req, session.session_id, tree.tree_connect_id)
    response: SMB2HeaderResponse = connection.receive(request)
    set_resp = SMB2SetInfoResponse()
    set_resp.unpack(response['data'].get_value())

    info_buffer = FileDispositionInformation()
    info_buffer['delete_pending'] = True
    set_req = SMB2SetInfoRequest()
    set_req['info_type'] = info_buffer.INFO_TYPE
    set_req['file_info_class'] = info_buffer.INFO_CLASS
    set_req['file_id'] = file_open.file_id
    set_req['buffer'] = info_buffer
    request: Request = connection.send(set_req, session.session_id, tree.tree_connect_id)
    response: SMB2HeaderResponse = connection.receive(request)
    set_resp = SMB2SetInfoResponse()
    set_resp.unpack(response['data'].get_value())
