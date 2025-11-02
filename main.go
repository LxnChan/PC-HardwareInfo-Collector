package main

import (
	"bufio"
    "bytes"
	"encoding/csv"
    "encoding/json"
	"flag"
	"fmt"
    "io"
    "net/http"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
    "syscall"
    "unsafe"

	"github.com/StackExchange/wmi"
    "golang.org/x/text/encoding/simplifiedchinese"
    "golang.org/x/text/transform"
)

// WMI struct definitions
type win32Processor struct {
	Name                   *string
	NumberOfCores          *uint32
	NumberOfLogicalProcessors *uint32
}

type win32PhysicalMemory struct {
	Capacity          *uint64
	SMBIOSMemoryType  *uint16
	MemoryType        *uint16
    Speed             *uint32
    ConfiguredClockSpeed *uint32
}

type win32BaseBoard struct {
	Product      *string
	SerialNumber *string
}

type win32LogicalDisk struct {
	DeviceID *string
}

type win32DiskPartition struct {
	DeviceID *string
}

type win32DiskDrive struct {
	Model       *string
	Size        *string
	PNPDeviceID *string
    InterfaceType *string
    MediaType   *string
}

type win32NetworkAdapterConfiguration struct {
	Description *string
	MACAddress  *string
	IPAddress   *[]string
	IPEnabled   *bool
}

type win32NetworkAdapter struct {
    Name            *string
    Description     *string
    MACAddress      *string
    PhysicalAdapter *bool
}

type win32VideoController struct {
	Name *string
}

type win32ComputerSystem struct {
    TotalPhysicalMemory *uint64
    Name *string
}

type win32OperatingSystem struct {
    Caption *string
    Version *string
    BuildNumber *string
}

// HardwareInfo 用于JSON序列化的硬件信息结构
type HardwareInfo struct {
    Timestamp           string `json:"timestamp"`
    Remark             string `json:"remark"`
    ComputerName       string `json:"computer_name"`
    OSVersion          string `json:"os_version"`
    KernelVersion      string `json:"kernel_version"`
    CPUModel           string `json:"cpu_model"`
    CPUCores           string `json:"cpu_cores"`
    MemoryGB            string `json:"memory_gb"`
    MemoryGeneration   string `json:"memory_generation"`
    BoardModel         string `json:"board_model"`
    BoardSerial        string `json:"board_serial"`
    SystemDiskModel    string `json:"system_disk_model"`
    SystemDiskGB       string `json:"system_disk_gb"`
    OtherDisks         string `json:"other_disks"`
    WiredAdapterModel  string `json:"wired_adapter_model"`
    WiredIP            string `json:"wired_ip"`
    WiredMAC           string `json:"wired_mac"`
    WiFiAdapterModel   string `json:"wifi_adapter_model"`
    WiFiIP             string `json:"wifi_ip"`
    WiFiMAC            string `json:"wifi_mac"`
    GPUInfo            string `json:"gpu_info"`
}

// Config 配置文件结构
type Config struct {
    ServerURL string `json:"server_url"`
}

func main() {
    // 解析命令行参数
    serverURL := flag.String("s", "", "服务器URL（如：https://example.com/api）")
    flag.Parse()
    
    // 如果未指定-s参数，尝试从conf.json读取
    finalServerURL := *serverURL
    if finalServerURL == "" {
        if config, err := readConfig(); err == nil && config.ServerURL != "" {
            finalServerURL = config.ServerURL
        }
    }
    
	cpuModel, cpuCores := getCPUInfo()
	memGB, memGen := getMemoryInfo()
	boardModel, boardSN := getBaseBoardInfo()
	sysDiskModel, sysDiskGB, systemPNP := getSystemDiskInfo()
	otherDisks := getOtherDisksInfo(systemPNP)
    wiredIP, wiredMAC, wifiIP, wifiMAC, wiredModel, wifiModel := getNetworkInfo()
    gpuInfo := getGPUInfo()
    compName := getComputerName()
    osCaption, kernelVer := getOSInfo()

    remark := promptRemark()

    header := []string{
        "备注",
        "计算机名称",
        "操作系统版本",
        "内核版本",
        "CPU型号",
        "CPU核心数",
        "内存容量(GB)",
        "内存代次",
        "主板型号",
        "主板序列号",
        "系统硬盘型号",
        "系统硬盘容量(GB)",
        "其他硬盘信息",
        "有线网卡型号",
        "有线IP",
        "有线MAC",
        "无线网卡型号",
        "无线IP",
        "无线MAC",
        "显卡信息",
    }

    row := []string{
        remark,
        compName,
        osCaption,
        kernelVer,
        cpuModel,
        cpuCores,
        memGB,
        memGen,
        boardModel,
        boardSN,
        sysDiskModel,
        sysDiskGB,
        otherDisks,
        wiredModel,
        wiredIP,
        wiredMAC,
        wifiModel,
        wifiIP,
        wifiMAC,
        gpuInfo,
    }

    writeCSV("hardware_info.csv", header, row)

    // 如果指定了服务器URL（命令行参数或配置文件），则发送JSON
    if finalServerURL != "" {
        sendToServer(finalServerURL, HardwareInfo{
            Timestamp:           fmt.Sprintf("%d", time.Now().UnixMilli()),
            Remark:             remark,
            ComputerName:       compName,
            OSVersion:          osCaption,
            KernelVersion:      kernelVer,
            CPUModel:           cpuModel,
            CPUCores:           cpuCores,
            MemoryGB:            memGB,
            MemoryGeneration:   memGen,
            BoardModel:         boardModel,
            BoardSerial:        boardSN,
            SystemDiskModel:    sysDiskModel,
            SystemDiskGB:       sysDiskGB,
            OtherDisks:         otherDisks,
            WiredAdapterModel:  wiredModel,
            WiredIP:            wiredIP,
            WiredMAC:           wiredMAC,
            WiFiAdapterModel:   wifiModel,
            WiFiIP:             wifiIP,
            WiFiMAC:            wifiMAC,
            GPUInfo:            gpuInfo,
        })
    }
}

func promptRemark() string {
	reader := bufio.NewReader(os.Stdin)
    fmt.Print("采集完成，请输入备注后回车（可留空）：")
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}

func getCPUInfo() (model string, cores string) {
	var dst []win32Processor
	_ = wmi.Query("SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor", &dst)
	if len(dst) == 0 {
		return "", ""
	}
	name := derefString(dst[0].Name)
	var coreCount uint32
	if dst[0].NumberOfCores != nil {
		coreCount = *dst[0].NumberOfCores
	}
	return name, fmt.Sprintf("%d", coreCount)
}

func getMemoryInfo() (totalGB string, generation string) {
    var mems []win32PhysicalMemory
    _ = wmi.Query("SELECT Capacity, SMBIOSMemoryType, MemoryType, Speed, ConfiguredClockSpeed FROM Win32_PhysicalMemory", &mems)
	if len(mems) == 0 {
        // 回退到系统总内存
        total := getSystemTotalMemory()
        return bytesToGBString(total), "NULL"
	}
	var total uint64
	gens := make(map[string]int)
	for _, m := range mems {
		if m.Capacity != nil {
			total += *m.Capacity
		}
        gen := mapDDRGeneration(m.SMBIOSMemoryType, m.MemoryType)
        if gen == "" || gen == "NULL" {
            // 频率回退判断（保守近似）
            var mhz uint32
            if m.ConfiguredClockSpeed != nil && *m.ConfiguredClockSpeed != 0 {
                mhz = *m.ConfiguredClockSpeed
            } else if m.Speed != nil {
                mhz = *m.Speed
            }
            if mhz != 0 {
                gen = guessDDRBySpeed(mhz)
            }
        }
		if gen != "" {
			gens[gen]++
		}
	}
	genPicked := ""
	if len(gens) > 0 {
		// pick the most frequent generation
		type kv struct{ k string; v int }
		var arr []kv
		for k, v := range gens { arr = append(arr, kv{k, v}) }
		sort.Slice(arr, func(i, j int) bool { return arr[i].v > arr[j].v })
		genPicked = arr[0].k
	}
    if genPicked == "" {
        genPicked = "NULL"
    }
    if total == 0 {
        total = getSystemTotalMemory()
    }
    return bytesToGBString(total), genPicked
}

func mapDDRGeneration(smbiosType *uint16, memType *uint16) string {
	val := uint16(0)
	if smbiosType != nil && *smbiosType != 0 {
		val = *smbiosType
	} else if memType != nil {
		val = *memType
	}
	switch val {
	case 20:
		return "DDR"
	case 21:
		return "DDR2"
	case 24:
		return "DDR3"
	case 26:
		return "DDR4"
	case 29:
		return "DDR5"
	default:
        return ""
	}
}

func guessDDRBySpeed(mhz uint32) string {
    // 非严格映射，仅用于无类型时的保守推断
    switch {
    case mhz >= 4000:
        return "DDR5"
    case mhz >= 2133:
        return "DDR4"
    case mhz >= 800:
        return "DDR3"
    case mhz >= 400:
        return "DDR2"
    case mhz > 0:
        return "DDR"
    default:
        return ""
    }
}

func getSystemTotalMemory() uint64 {
    var cs []win32ComputerSystem
    _ = wmi.Query("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem", &cs)
    if len(cs) > 0 && cs[0].TotalPhysicalMemory != nil {
        return *cs[0].TotalPhysicalMemory
    }
    return 0
}

func getComputerName() string {
    // 优先 WMI
    var cs []win32ComputerSystem
    _ = wmi.Query("SELECT Name FROM Win32_ComputerSystem", &cs)
    if len(cs) > 0 {
        name := strings.TrimSpace(derefString(cs[0].Name))
        if name != "" {
            return name
        }
    }
    // 回退主机名
    if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
        return strings.TrimSpace(h)
    }
    // 回退环境变量
    if v := strings.TrimSpace(os.Getenv("COMPUTERNAME")); v != "" {
        return v
    }
    return ""
}

func getOSInfo() (caption, kernel string) {
    var oses []win32OperatingSystem
    _ = wmi.Query("SELECT Caption, Version, BuildNumber FROM Win32_OperatingSystem", &oses)
    if len(oses) > 0 {
        caption = strings.TrimSpace(derefString(oses[0].Caption))
        v := strings.TrimSpace(derefString(oses[0].Version))
        // 以 Version 作为“内核版本”，如 10.0.22631
        kernel = v
    }
    return
}

func getBaseBoardInfo() (model string, sn string) {
	var bb []win32BaseBoard
	_ = wmi.Query("SELECT Product, SerialNumber FROM Win32_BaseBoard", &bb)
	if len(bb) == 0 {
		return "", ""
	}
	return derefString(bb[0].Product), derefString(bb[0].SerialNumber)
}

func getSystemDiskInfo() (model string, sizeGB string, pnp string) {
	// Determine system drive (usually C:)
	sysDrive := strings.ToUpper(os.Getenv("SystemDrive"))
	if sysDrive == "" {
		sysDrive = "C:"
	}
	// ASSOCIATORS from logical disk to partition
	var parts []win32DiskPartition
	q1 := fmt.Sprintf("ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='%s'} WHERE AssocClass=Win32_LogicalDiskToPartition", escapeWMIString(sysDrive))
	_ = wmi.Query(q1, &parts)
	if len(parts) == 0 || parts[0].DeviceID == nil {
		return "", "", ""
	}
	// ASSOCIATORS from partition to disk drive
	var drives []win32DiskDrive
	q2 := fmt.Sprintf("ASSOCIATORS OF {Win32_DiskPartition.DeviceID='%s'} WHERE AssocClass=Win32_DiskDriveToDiskPartition", escapeWMIString(*parts[0].DeviceID))
	_ = wmi.Query(q2, &drives)
	if len(drives) == 0 {
		return "", "", ""
	}
	mdl := derefString(drives[0].Model)
	sizeBytes := parseUintString(derefString(drives[0].Size))
	return mdl, bytesToGBString(sizeBytes), derefString(drives[0].PNPDeviceID)
}

func getOtherDisksInfo(systemPNP string) string {
    var drives []win32DiskDrive
    _ = wmi.Query("SELECT Model, Size, PNPDeviceID, InterfaceType, MediaType FROM Win32_DiskDrive", &drives)
	if len(drives) == 0 {
		return ""
	}
	items := make([]string, 0)
	for _, d := range drives {
		pnp := strings.TrimSpace(strings.ToUpper(derefString(d.PNPDeviceID)))
		if systemPNP != "" && strings.EqualFold(pnp, strings.ToUpper(systemPNP)) {
			continue
		}
        if isRemovableOrOptical(d) {
            continue
        }
		model := strings.TrimSpace(derefString(d.Model))
		sizeGB := bytesToGBString(parseUintString(derefString(d.Size)))
		if model == "" && sizeGB == "" {
			continue
		}
		if model == "" { model = "(未知型号)" }
		items = append(items, fmt.Sprintf("%s %sGB", model, sizeGB))
	}
	return strings.Join(items, " | ")
}

func isRemovableOrOptical(d win32DiskDrive) bool {
    iface := strings.ToUpper(strings.TrimSpace(derefString(d.InterfaceType)))
    media := strings.ToUpper(strings.TrimSpace(derefString(d.MediaType)))
    model := strings.ToUpper(strings.TrimSpace(derefString(d.Model)))
    // 明确的 USB/可移动/光驱排除
    if iface == "USB" {
        return true
    }
    if strings.Contains(media, "REMOVABLE") || strings.Contains(media, "EXTERNAL") || strings.Contains(media, "CD") || strings.Contains(media, "DVD") {
        return true
    }
    if strings.Contains(model, "USB") || strings.Contains(model, "DVD") || strings.Contains(model, "CD-ROM") {
        return true
    }
    return false
}

func getNetworkInfo() (wiredIP, wiredMAC, wifiIP, wifiMAC, wiredModel, wifiModel string) {
	var nics []win32NetworkAdapterConfiguration
	_ = wmi.Query("SELECT Description, MACAddress, IPAddress, IPEnabled FROM Win32_NetworkAdapterConfiguration", &nics)
    // 先从已启用的配置里尽量获取 IP/MAC
	for _, nic := range nics {
		if nic.IPEnabled == nil || !*nic.IPEnabled {
			continue
		}
		desc := strings.ToLower(derefString(nic.Description))
		if isVirtualAdapter(desc) {
			continue
		}
		ip := firstIPv4(nic.IPAddress)
        mac := formatMACDashed(strings.TrimSpace(derefString(nic.MACAddress)))
		if ip == "" && mac == "" {
			continue
		}
		if isWireless(desc) {
			if wifiIP == "" { wifiIP = ip }
			if wifiMAC == "" { wifiMAC = mac }
        } else if isWired(desc) {
			if wiredIP == "" { wiredIP = ip }
			if wiredMAC == "" { wiredMAC = mac }
		} else {
			// fallback: if neither classified, prefer to fill wired if empty
			if wiredIP == "" { wiredIP = ip }
			if wiredMAC == "" { wiredMAC = mac }
		}
	}
    // 再查询网卡对象，即使未连接也能拿到 MAC 与型号
    var adapters []win32NetworkAdapter
    _ = wmi.Query("SELECT Name, Description, MACAddress, PhysicalAdapter FROM Win32_NetworkAdapter", &adapters)
    for _, ad := range adapters {
        desc := strings.ToLower(strings.TrimSpace(derefString(ad.Description)))
        if isVirtualAdapter(desc) { continue }
        if ad.PhysicalAdapter != nil && !*ad.PhysicalAdapter { continue }
        name := strings.TrimSpace(derefString(ad.Name))
        mac := formatMACDashed(strings.TrimSpace(derefString(ad.MACAddress)))
        if isWireless(desc) {
            if wifiModel == "" { wifiModel = name }
            if wifiMAC == "" { wifiMAC = mac }
        } else if isWired(desc) {
            if wiredModel == "" { wiredModel = name }
            if wiredMAC == "" { wiredMAC = mac }
        }
    }
    return
}

func isVirtualAdapter(desc string) bool {
	patterns := []string{
		"vbox", "virtual", "vmware", "hyper-v", "hyperv", "loopback", "tap-", "tunnel", "bluetooth", "npcap", "wireshark",
	}
	for _, p := range patterns {
		if strings.Contains(desc, p) { return true }
	}
	return false
}

func isWireless(desc string) bool {
	patterns := []string{"wireless", "wi-fi", "wifi", "802.11", "wlan"}
	for _, p := range patterns {
		if strings.Contains(desc, p) { return true }
	}
	return false
}

func isWired(desc string) bool {
	patterns := []string{"ethernet", "gigabit", "controller", "rtl8", "intel(r) ethernet", "realtek pci"}
	for _, p := range patterns {
		if strings.Contains(desc, p) { return true }
	}
	return false
}

func firstIPv4(ipArr *[]string) string {
	if ipArr == nil { return "" }
	for _, ip := range *ipArr {
		parsed := net.ParseIP(ip)
		if parsed != nil && parsed.To4() != nil {
			return parsed.String()
		}
	}
	return ""
}

func formatMACDashed(mac string) string {
    if mac == "" { return "" }
    s := strings.ToLower(mac)
    // remove common separators
    s = strings.ReplaceAll(s, ":", "")
    s = strings.ReplaceAll(s, "-", "")
    s = strings.ReplaceAll(s, ".", "")
    if len(s) < 12 {
        // pad or return empty if invalid
        return ""
    }
    s = s[:12]
    return s[0:4] + "-" + s[4:8] + "-" + s[8:12]
}

func getGPUInfo() string {
	var gpus []win32VideoController
	_ = wmi.Query("SELECT Name FROM Win32_VideoController", &gpus)
	if len(gpus) == 0 {
		return ""
	}
	names := make([]string, 0, len(gpus))
	for _, g := range gpus {
		name := strings.TrimSpace(derefString(g.Name))
		if name != "" {
			names = append(names, name)
		}
	}
	return strings.Join(names, " | ")
}

func writeCSV(filename string, header, row []string) {
    path := filepath.Join(".", filename)
    // 以追加方式打开，若不存在则创建
    needHeader := false
    if _, err := os.Stat(path); os.IsNotExist(err) {
        needHeader = true
    }
    f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
    if err != nil {
        fmt.Println("写入CSV失败:", err)
        return
    }
    defer f.Close()
    // 输出为 ANSI(GBK) 编码
    tw := transform.NewWriter(f, simplifiedchinese.GBK.NewEncoder())
    w := csv.NewWriter(tw)
    w.UseCRLF = true
    if needHeader {
        _ = w.Write(header)
    }
    _ = w.Write(row)
    w.Flush()
    _ = tw.Close()
    _ = f.Sync()
    fmt.Printf("已写入 %s\n", path)
}

func derefString(p *string) string {
	if p == nil { return "" }
	return *p
}

func parseUintString(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" { return 0 }
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil { return 0 }
	return v
}

func bytesToGBString(b uint64) string {
	if b == 0 { return "" }
	const gb = 1024 * 1024 * 1024
	val := float64(b) / float64(gb)
	// round to 0.1 GB for readability
	return strconv.FormatFloat(roundTo(val, 0.1), 'f', -1, 64)
}

func roundTo(v, step float64) float64 {
	if step <= 0 { return v }
	r := v/step
	return float64(int64(r+0.5)) * step
}

func escapeWMIString(s string) string {
	// double quotes inside WQL identifiers are uncommon here; still sanitize
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "''")
	return s
}

// readConfig 读取同目录下的conf.json配置文件
func readConfig() (*Config, error) {
	configPath := filepath.Join(".", "conf.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		// 文件不存在或其他错误，返回空配置
		return nil, err
	}
	
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	
	return &config, nil
}

// sendToServer 将硬件信息以JSON格式POST到指定服务器
func sendToServer(url string, info HardwareInfo) {
	jsonData, err := json.Marshal(info)
	if err != nil {
		fmt.Printf("JSON序列化失败: %v\n", err)
		return
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("发送到服务器失败: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Printf("已成功发送到服务器: %s\n", url)
	} else {
		fmt.Printf("服务器返回错误 (状态码: %d): %s\n", resp.StatusCode, string(body))
	}
}

// ensure program link time imports are used (avoid unused import on older toolchains)
var _ = time.Now
var _ = regexp.MustCompile

// showStartWindow 弹出一个简单的消息框，提示即将开始采集
func showStartWindow() {
    user32 := syscall.NewLazyDLL("user32.dll")
    proc := user32.NewProc("MessageBoxW")
    title := syscall.StringToUTF16Ptr("PCConfCollector")
    text := syscall.StringToUTF16Ptr("即将开始采集硬件信息，点击\"确定\"开始……")
    // MB_OK | MB_ICONINFORMATION = 0x00000000 | 0x00000040 = 0x40
    // hwnd=0, text, title
    _, _, _ = proc.Call(0,
        uintptr(unsafe.Pointer(text)),
        uintptr(unsafe.Pointer(title)),
        uintptr(0x40))
}


