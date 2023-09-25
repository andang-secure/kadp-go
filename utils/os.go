package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

func GetOsInfo() string {

	goos := runtime.GOOS
	var osInfo string

	if goos == "linux" {
		osInfo, _ = linuxOsInfo()

	} else if goos == "windows" {
		osInfo, _ = windowsOsInfo()

	} else if goos == "darwin" {
		osInfo, _ = macOsInfo()
		// 获取 macOS 系统的详细信息的方法
	}
	return osInfo

}

func windowsOsInfo() (string, error) {
	// 执行命令获取操作系统信息
	cmd := exec.Command("cmd", "/c", "wmic os get Caption /value")
	out, err := cmd.Output()
	if err != nil {
		fmt.Printf("Unable to obtain system" + err.Error())
		return "", err
	}
	// 提取操作系统型号并去除特定部分
	osModel := extractWindowsOSModel(string(out))
	osModel = strings.TrimPrefix(osModel, "Microsoft ")
	cleanStr := removeInvalidChars(osModel)

	return cleanStr, nil
}

func extractWindowsOSModel(output string) string {
	// 从输出中提取操作系统型号
	osModel := ""
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Caption=") {
			osModel = strings.TrimPrefix(line, "Caption=")
			break
		}
	}
	return osModel
}

func removeInvalidChars(str string) string {
	// 定义匹配非 ASCII 字符的正则表达式
	regex := regexp.MustCompile("[^[:ascii:]]")

	// 使用空字符串替换匹配到的乱码字符
	cleanStr := regex.ReplaceAllString(str, "")

	return cleanStr
}

func linuxOsInfo() (string, error) {
	// 读取 /etc/os-release 文件
	data, err := ioutil.ReadFile("/etc/os-release")
	if err != nil {
		fmt.Printf("Unable to obtain system" + err.Error())

		return "", err
	}
	// 提取系统型号
	osModel := extractLinuxOSModel(string(data))
	return osModel, nil
}

func extractLinuxOSModel(data string) string {
	// 提取系统型号
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			osModel := strings.TrimPrefix(line, "PRETTY_NAME=")
			osModel = strings.Trim(osModel, `"`)

			return osModel
		}
	}

	return ""
}

func macOsInfo() (string, error) {
	// 执行 sw_vers 命令
	out, err := exec.Command("sw_vers").Output()
	if err != nil {
		fmt.Println("Unable to obtain system" + err.Error())
		return "", err
	}

	// 解析输出文本，提取版本信息
	version := extractMacOSVersion(string(out))
	return version, nil
}

func extractMacOSVersion(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ProductVersion:") {
			version := strings.TrimSpace(strings.TrimPrefix(line, "ProductVersion:"))
			return version
		}
	}

	return ""
}

func GetMac() string {

	goos := runtime.GOOS
	var osInfo string

	if goos == "linux" {
		osInfo, _ = getLinuxMac()

	} else if goos == "windows" {
		osInfo, _ = getWindowsMac()

	} else if goos == "darwin" {
		osInfo, _ = getMACMac()
		// 获取 macOS 系统的详细信息的方法
	}
	return osInfo

}

func getWindowsMac() (macAddr string, err error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("Failed to get net interfaces: %v\n", err)
		return "", err
	}

	for _, iface := range interfaces {
		if (iface.Flags&net.FlagUp) != 0 && (iface.Flags&net.FlagLoopback) == 0 && !isVirtualInterface(iface) {
			macAddr = iface.HardwareAddr.String()
			if len(macAddr) > 0 {
				return macAddr, nil
			}
		}
	}

	return "", fmt.Errorf("no active physical MAC address found")
}

func isVirtualInterface(iface net.Interface) bool {
	virtualInterfaces := []string{"VMware", "VirtualBox", "Parallels", "TAP", "TUN", "VPN"}
	name := iface.Name

	for _, v := range virtualInterfaces {
		if strings.Contains(name, v) {
			return true
		}
	}

	return false
}

func getLinuxMac() (macAddr string, err error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("Failed to get net interfaces: %v\n", err)
		return "", err
	}

	for _, iface := range interfaces {
		if !isLinuxVirtualInterface(iface.Name) {
			macAddr, err = getPhysicalMacAddress(iface.Name)
			if err == nil && len(macAddr) > 0 {
				return macAddr, nil
			}
		}
	}

	return "", fmt.Errorf("no active physical MAC address found")
}

func isLinuxVirtualInterface(ifaceName string) bool {
	virtualInterfaces := []string{"vmnet", "virbr", "veth", "docker", "lo"}

	for _, v := range virtualInterfaces {
		if strings.HasPrefix(ifaceName, v) {
			return true
		}
	}

	return false
}

func getPhysicalMacAddress(ifaceName string) (macAddr string, err error) {
	sysPath := fmt.Sprintf("/sys/class/net/%s/device", ifaceName)
	devicePath, err := filepath.EvalSymlinks(sysPath)
	if err != nil {
		return "", err
	}

	phyPath := filepath.Join(devicePath, "phy80211", "net", ifaceName, "address")
	macBytes, err := ioutil.ReadFile(phyPath)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(macBytes)), nil
}

func getMACMac() (macAddr string, err error) {
	interfaces, err := getNetworkInterfaces()
	if err != nil {
		fmt.Printf("Failed to get network interfaces: %v\n", err)
		return "", err
	}

	for _, iface := range interfaces {
		if !isMacVirtualInterface(iface) {
			macAddr, err = getPhysicalMacAddress(iface)
			if err == nil && len(macAddr) > 0 {
				return macAddr, nil
			}
		}
	}

	return "", fmt.Errorf("no active physical MAC address found")
}

func getNetworkInterfaces() ([]string, error) {
	cmd := exec.Command("networksetup", "-listallhardwareports")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	interfaces := []string{}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Hardware Port: ") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				interfaces = append(interfaces, fields[2])
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return interfaces, nil
}

func isMacVirtualInterface(iface string) bool {
	virtualInterfaces := []string{"vmnet", "vnic", "tun", "tap", "utun"}

	for _, v := range virtualInterfaces {
		if strings.Contains(iface, v) {
			return true
		}
	}

	return false
}

func getMacPhysicalMacAddress(iface string) (string, error) {
	cmd := exec.Command("ifconfig", iface)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "ether ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1], nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("no MAC address found for %s", iface)
}

func GetOutBoundIP() (ip string, err error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "", err
	}
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	//fmt.Println(localAddr.String())
	ip = strings.Split(localAddr.String(), ":")[0]
	return ip, nil
}
