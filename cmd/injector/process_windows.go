//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	th32csSnapProcess       = 0x00000002
	th32csSnapModule        = 0x00000008
	th32csSnapModule32      = 0x00000010
	processCreateThread     = 0x0002
	processVMOperation      = 0x0008
	processVMWrite          = 0x0020
	processQueryInfo        = 0x0400
	processQueryLimited     = 0x1000
	memCommit               = 0x1000
	memReserve              = 0x2000
	memRelease              = 0x8000
	pageReadWrite           = 0x04
	waitObject0             = 0
	waitTimeout             = 258
	imageFileMachineI386    = 0x014c
	imageFileMachineAMD64   = 0x8664
	imageFileMachineUnknown = 0
)

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	pSnapshot            = kernel32.NewProc("CreateToolhelp32Snapshot")
	pProcess32First      = kernel32.NewProc("Process32FirstW")
	pProcess32Next       = kernel32.NewProc("Process32NextW")
	pModule32First       = kernel32.NewProc("Module32FirstW")
	pModule32Next        = kernel32.NewProc("Module32NextW")
	pOpenProcess         = kernel32.NewProc("OpenProcess")
	pCloseHandle         = kernel32.NewProc("CloseHandle")
	pIsWow64Process2     = kernel32.NewProc("IsWow64Process2")
	pIsWow64Process      = kernel32.NewProc("IsWow64Process")
	pVirtualAllocEx      = kernel32.NewProc("VirtualAllocEx")
	pVirtualFreeEx       = kernel32.NewProc("VirtualFreeEx")
	pWriteProcessMemory  = kernel32.NewProc("WriteProcessMemory")
	pCreateRemoteThread  = kernel32.NewProc("CreateRemoteThread")
	pWaitForSingleObject = kernel32.NewProc("WaitForSingleObject")
	pLoadLibraryW        = kernel32.NewProc("LoadLibraryW")
)

var gameProcessRE = regexp.MustCompile(`(?i)(gmod|hl2)`)

type processEntry32 struct {
	Size          uint32
	Usage         uint32
	ProcessID     uint32
	DefaultHeapID uintptr
	ModuleID      uint32
	Threads       uint32
	ParentID      uint32
	Priority      int32
	Flags         uint32
	ExeFile       [260]uint16
}

type moduleEntry32 struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlobalUsage  uint32
	ProcessUsage uint32
	BaseAddr     uintptr
	BaseSize     uint32
	HModule      uintptr
	Module       [256]uint16
	ExePath      [260]uint16
}

type gameProcess struct {
	pid  uint32
	name string
}
type loadedModule struct {
	name, path string
	base, size uintptr
}

func winErr(op string, e error) error {
	if e == nil || e == syscall.Errno(0) {
		return errors.New(op + " failed")
	}
	return fmt.Errorf("%s: %w", op, e)
}

func closeHandle(h uintptr) {
	if h != 0 && h != ^uintptr(0) {
		_, _, _ = pCloseHandle.Call(h)
	}
}

func processes() ([]gameProcess, error) {
	snap, _, err := pSnapshot.Call(th32csSnapProcess, 0)
	if snap == ^uintptr(0) {
		return nil, winErr("CreateToolhelp32Snapshot(process)", err)
	}
	defer closeHandle(snap)
	item := processEntry32{Size: uint32(unsafe.Sizeof(processEntry32{}))}
	ok, _, e := pProcess32First.Call(snap, uintptr(unsafe.Pointer(&item)))
	if ok == 0 {
		return nil, winErr("Process32FirstW", e)
	}
	found := make([]gameProcess, 0, 4)
	for {
		name := syscall.UTF16ToString(item.ExeFile[:])
		if gameProcessRE.MatchString(name) {
			found = append(found, gameProcess{pid: item.ProcessID, name: name})
		}
		ok, _, _ = pProcess32Next.Call(snap, uintptr(unsafe.Pointer(&item)))
		if ok == 0 {
			break
		}
	}
	return found, nil
}

func modules(pid uint32) ([]loadedModule, error) {
	// ERROR_BAD_LENGTH is transient while the module list is changing.
	var snap uintptr
	var err error
	for i := 0; i < 5; i++ {
		snap, _, err = pSnapshot.Call(th32csSnapModule|th32csSnapModule32, uintptr(pid))
		if snap != ^uintptr(0) {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if snap == ^uintptr(0) {
		return nil, winErr("CreateToolhelp32Snapshot(modules)", err)
	}
	defer closeHandle(snap)
	item := moduleEntry32{Size: uint32(unsafe.Sizeof(moduleEntry32{}))}
	ok, _, e := pModule32First.Call(snap, uintptr(unsafe.Pointer(&item)))
	if ok == 0 {
		return nil, winErr("Module32FirstW", e)
	}
	found := make([]loadedModule, 0, 32)
	for {
		found = append(found, loadedModule{
			name: strings.ToLower(syscall.UTF16ToString(item.Module[:])),
			path: syscall.UTF16ToString(item.ExePath[:]),
			base: item.BaseAddr,
			size: uintptr(item.BaseSize),
		})
		ok, _, _ = pModule32Next.Call(snap, uintptr(unsafe.Pointer(&item)))
		if ok == 0 {
			break
		}
	}
	return found, nil
}

func targetBits(h uintptr) (int, error) {
	// Modern Windows, including ARM64 hosts with x86/x64 emulation.
	if err := pIsWow64Process2.Find(); err == nil {
		var procMachine, nativeMachine uint16
		ok, _, e := pIsWow64Process2.Call(h, uintptr(unsafe.Pointer(&procMachine)), uintptr(unsafe.Pointer(&nativeMachine)))
		if ok == 0 {
			return 0, winErr("IsWow64Process2", e)
		}
		machine := procMachine
		if machine == imageFileMachineUnknown {
			machine = nativeMachine
		}
		switch machine {
		case imageFileMachineI386:
			return 32, nil
		case imageFileMachineAMD64:
			return 64, nil
		default:
			return 0, fmt.Errorf("unsupported process machine: 0x%x", machine)
		}
	}
	// Windows versions without IsWow64Process2: compare WOW64 status.
	var wow uint32
	ok, _, e := pIsWow64Process.Call(h, uintptr(unsafe.Pointer(&wow)))
	if ok == 0 {
		return 0, winErr("IsWow64Process", e)
	}
	if wow != 0 {
		return 32, nil
	}
	if unsafe.Sizeof(uintptr(0)) == 8 {
		return 64, nil
	}
	return 32, nil
}

func remoteLoadLibrary(localModules, remoteModules []loadedModule) (uintptr, error) {
	localAddr := pLoadLibraryW.Addr()
	for _, local := range localModules {
		if localAddr < local.base || localAddr-local.base >= local.size {
			continue
		}
		for _, remote := range remoteModules {
			if remote.name == local.name {
				return remote.base + (localAddr - local.base), nil
			}
		}
		return 0, fmt.Errorf("target has not loaded %s", local.name)
	}
	return 0, errors.New("cannot locate local LoadLibraryW owning module")
}

func inject(pid uint32, path string, bits int) (bool, error) {
	rights := uintptr(processCreateThread | processVMOperation | processVMWrite | processQueryInfo | processQueryLimited)
	h, _, err := pOpenProcess.Call(rights, 0, uintptr(pid))
	if h == 0 {
		return false, winErr("OpenProcess", err)
	}
	defer closeHandle(h)
	target, err := targetBits(h)
	if err != nil {
		return false, err
	}
	if target != bits {
		return false, nil
	}

	remoteMods, err := modules(pid)
	if err != nil {
		return false, err
	}
	for _, m := range remoteMods {
		if strings.EqualFold(m.path, path) {
			return true, nil
		} // already injected
	}
	localMods, err := modules(uint32(os.Getpid()))
	if err != nil {
		return false, err
	}
	addr, err := remoteLoadLibrary(localMods, remoteMods)
	if err != nil {
		return false, err
	}

	widePath, err := syscall.UTF16FromString(path)
	if err != nil {
		return false, err
	}
	byteSize := uintptr(len(widePath) * 2)
	remoteData, _, allocErr := pVirtualAllocEx.Call(h, 0, byteSize, memCommit|memReserve, pageReadWrite)
	if remoteData == 0 {
		return false, winErr("VirtualAllocEx", allocErr)
	}
	// Never free remoteData while the thread is still using the string.
	safeToFree := false
	defer func() {
		if safeToFree {
			_, _, _ = pVirtualFreeEx.Call(h, remoteData, 0, memRelease)
		}
	}()
	var written uintptr
	ok, _, writeErr := pWriteProcessMemory.Call(h, remoteData, uintptr(unsafe.Pointer(&widePath[0])), byteSize, uintptr(unsafe.Pointer(&written)))
	if ok == 0 || written != byteSize {
		safeToFree = true
		return false, winErr("WriteProcessMemory", writeErr)
	}
	thread, _, createErr := pCreateRemoteThread.Call(h, 0, 0, addr, remoteData, 0, 0)
	if thread == 0 {
		safeToFree = true
		return false, winErr("CreateRemoteThread", createErr)
	}
	defer closeHandle(thread)
	wait, _, waitErr := pWaitForSingleObject.Call(thread, 15000)
	if wait == waitTimeout {
		return false, errors.New("remote LoadLibraryW timeout")
	}
	if wait != waitObject0 {
		return false, winErr("WaitForSingleObject", waitErr)
	}
	safeToFree = true

	// Check the module table instead of using GetExitCodeThread: HMODULE is
	// pointer-sized but thread exit codes are DWORD, which truncates on x64.
	for i := 0; i < 20; i++ {
		list, err := modules(pid)
		if err == nil {
			for _, mod := range list {
				if strings.EqualFold(mod.path, path) {
					return true, nil
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false, errors.New("LoadLibraryW completed but DLL was not found in target process")
}
