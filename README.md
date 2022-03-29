# CVE-2021-44142 Vulnerability Checker
A tool to check if a Samba server is vulnerable to CVE-2021-44142

## Background
CVE-2021-44142 is a heap out-of-bounds read and write in Samba's vfs_fruit module used at Pwn2Own Austin 2021 against the Western Digital PR4100. It was first discovered by [Nguyễn Hoàng Thạch](https://twitter.com/hi_im_d4rkn3ss) and [Billy Jheng Bing-Jhong](https://twitter.com/st424204) of STAR Labs. [Orange Tsai](https://twitter.com/orange_8361) of DEVCORE also reported this vulnerability. This work is based off a blog post by [0xsha](https://twitter.com/0xsha) at https://0xsha.io/blog/a-samba-horror-story-cve-2021-44142.

This tool demonstrates vulnerability to CVE-2021-44142 by dumping a talloc heap cookie and linked list pointer. Similar techniques can be used to write this data.

This work expands on the work of 0xsha by:
* Doing all the work required for the exploit in a single SMB connection. This is required as Samba can handle each connection in a different process. Using a single connection also makes debugging easier.
* Making the SMB connection look like it is coming from OSX. Western Digital has a custom patch to Samba that disables the vulnerable VFS modules unless the connection looks like it came from OSX.

## Usage
```
python check_vulnerable.py 
usage: check_vulnerable.py [-h] [--password PASSWORD] server port share user
check_vulnerable.py: error: the following arguments are required: server, port, share, user

```
## Example
```
python check_vulnerable.py 192.168.1.183 445 TimeMachineBackup Guest
{
    "vulnerable": true,
    "heap_cookie_leak": "0xfc571370",
    "heap_pointer_leak": "0x55e4e717b1b0",
    "fail_reason": ""
}
```