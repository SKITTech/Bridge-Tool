import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import { Copy, Download, Network, AlertTriangle, CheckCircle, Info } from "lucide-react";

interface BridgeConfig {
  osType: string;
  ipAddress: string;
  netmask: string;
  gateway: string;
  bridgeName: string;
  physicalInterface: string;
  ipv6Address: string;
  ipv6Gateway: string;
  ipv6Prefix: string;
  dnsServers: string;
  enableStp: boolean;
  enableIpv6: boolean;
  mtu: string;
  isHetzner: boolean;
}

interface GeneratedCommand {
  title: string;
  description: string;
  commands: string[];
  files?: Array<{
    path: string;
    content: string;
  }>;
}

export default function BridgeGenerator() {
  const { toast } = useToast();
  const [config, setConfig] = useState<BridgeConfig>({
    osType: "",
    ipAddress: "",
    netmask: "",
    gateway: "",
    bridgeName: "viifbr0",
    physicalInterface: "eth0",
    ipv6Address: "",
    ipv6Gateway: "",
    ipv6Prefix: "64",
    dnsServers: "8.8.8.8,8.8.4.4",
    enableStp: false,
    enableIpv6: false,
    mtu: "1500",
    isHetzner: false
  });

  const [generatedCommands, setGeneratedCommands] = useState<GeneratedCommand[]>([]);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [autoFillText, setAutoFillText] = useState("");

  const validateIP = (ip: string): boolean => {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(ip);
  };

  const validateIPv6 = (ip: string): boolean => {
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
    return ipv6Regex.test(ip);
  };

  const validateNetmask = (netmask: string): boolean => {
    if (netmask.includes('/')) {
      const prefix = parseInt(netmask.split('/')[1]);
      return prefix >= 1 && prefix <= 32;
    }
    // Validate dotted decimal netmask
    const netmaskValues = [
      "255.255.255.255", "255.255.255.254", "255.255.255.252", "255.255.255.248",
      "255.255.255.240", "255.255.255.224", "255.255.255.192", "255.255.255.128",
      "255.255.255.0", "255.255.254.0", "255.255.252.0", "255.255.248.0",
      "255.255.240.0", "255.255.224.0", "255.255.192.0", "255.255.128.0",
      "255.255.0.0", "255.254.0.0", "255.252.0.0", "255.248.0.0",
      "255.240.0.0", "255.224.0.0", "255.192.0.0", "255.128.0.0",
      "255.0.0.0", "254.0.0.0", "252.0.0.0", "248.0.0.0",
      "240.0.0.0", "224.0.0.0", "192.0.0.0", "128.0.0.0"
    ];
    return netmaskValues.includes(netmask);
  };

  const getNetmaskOptions = () => [
    { value: "/30", label: "/30 - 255.255.255.252" },
    { value: "/29", label: "/29 - 255.255.255.248" },
    { value: "/28", label: "/28 - 255.255.255.240" },
    { value: "/27", label: "/27 - 255.255.255.224" },
    { value: "/26", label: "/26 - 255.255.255.192" },
    { value: "/25", label: "/25 - 255.255.255.128" },
    { value: "/24", label: "/24 - 255.255.255.0" },
    { value: "/23", label: "/23 - 255.255.254.0" },
    { value: "/22", label: "/22 - 255.255.252.0" },
    { value: "/21", label: "/21 - 255.255.248.0" },
    { value: "/20", label: "/20 - 255.255.240.0" },
    { value: "/19", label: "/19 - 255.255.224.0" },
    { value: "/18", label: "/18 - 255.255.192.0" },
    { value: "/17", label: "/17 - 255.255.128.0" },
    { value: "/16", label: "/16 - 255.255.0.0" },
    { value: "/8", label: "/8 - 255.0.0.0" }
  ];

  const detectHetzner = (ip: string): boolean => {
    if (!validateIP(ip)) return false;
    const parts = ip.split('.').map(Number);
    // Hetzner IP ranges
    return (
      (parts[0] === 78 && parts[1] >= 46 && parts[1] <= 47) ||
      (parts[0] === 88 && parts[1] >= 198 && parts[1] <= 199) ||
      (parts[0] === 94 && parts[1] >= 130 && parts[1] <= 131) ||
      (parts[0] === 116 && parts[1] >= 202 && parts[1] <= 203) ||
      (parts[0] === 138 && parts[1] >= 201 && parts[1] <= 201) ||
      (parts[0] === 144 && parts[1] >= 76 && parts[1] <= 76) ||
      (parts[0] === 148 && parts[1] >= 251 && parts[1] <= 251) ||
      (parts[0] === 159 && parts[1] >= 69 && parts[1] <= 69) ||
      (parts[0] === 162 && parts[1] >= 55 && parts[1] <= 55) ||
      (parts[0] === 168 && parts[1] >= 119 && parts[1] <= 119) ||
      (parts[0] === 176 && parts[1] >= 9 && parts[1] <= 9) ||
      (parts[0] === 188 && parts[1] >= 40 && parts[1] <= 40) ||
      (parts[0] === 195 && parts[1] >= 201 && parts[1] <= 201) ||
      (parts[0] === 213 && parts[1] >= 133 && parts[1] <= 133)
    );
  };

  const validateConfig = (): boolean => {
    const newErrors: Record<string, string> = {};

    if (!config.osType) {
      newErrors.osType = "Please select an operating system";
    }

    if (!config.ipAddress) {
      newErrors.ipAddress = "IP address is required";
    } else if (!validateIP(config.ipAddress)) {
      newErrors.ipAddress = "Invalid IP address format";
    } else {
      // Auto-detect Hetzner and update state if needed
      const isHetznerIP = detectHetzner(config.ipAddress);
      if (isHetznerIP !== config.isHetzner) {
        setConfig(prev => ({ ...prev, isHetzner: isHetznerIP }));
      }
    }

    if (!config.netmask) {
      newErrors.netmask = "Netmask is required";
    } else if (!validateNetmask(config.netmask)) {
      newErrors.netmask = "Invalid netmask format";
    }

    if (!config.gateway) {
      newErrors.gateway = "Gateway is required";
    } else if (!validateIP(config.gateway)) {
      newErrors.gateway = "Invalid gateway IP address";
    }

    if (!config.bridgeName.trim()) {
      newErrors.bridgeName = "Bridge name is required";
    }

    if (!config.physicalInterface.trim()) {
      newErrors.physicalInterface = "Physical interface is required";
    }

    if (config.enableIpv6) {
      if (!config.ipv6Address) {
        newErrors.ipv6Address = "IPv6 address is required when IPv6 is enabled";
      } else if (!validateIPv6(config.ipv6Address)) {
        newErrors.ipv6Address = "Invalid IPv6 address format";
      }

      if (!config.ipv6Gateway) {
        newErrors.ipv6Gateway = "IPv6 gateway is required when IPv6 is enabled";
      } else if (!validateIPv6(config.ipv6Gateway)) {
        newErrors.ipv6Gateway = "Invalid IPv6 gateway format";
      }
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const parseNetworkConfig = (configText: string): void => {
    console.log("Starting to parse configuration:", configText);
    const lines = configText.split('\n');
    const parsedConfig: Partial<BridgeConfig> = {};

    // Auto-detect operating system from configuration style
    const detectOS = (text: string): string => {
      const lowerText = text.toLowerCase();
      if (lowerText.includes('netplan') || lowerText.includes('addresses:') || lowerText.includes('gateway4:')) {
        return 'ubuntu18';
      } else if (lowerText.includes('nmcli') || lowerText.includes('networkmanager')) {
        return 'almalinux8';
      } else if (lowerText.includes('auto ') && lowerText.includes('iface ') && lowerText.includes('inet static')) {
        return 'ubuntu';
      } else if (lowerText.includes('device=') && lowerText.includes('bootproto=') && lowerText.includes('onboot=')) {
        return 'centos7';
      }
      return '';
    };

    const detectedOS = detectOS(configText);
    if (detectedOS) {
      console.log("Auto-detected OS:", detectedOS);
      parsedConfig.osType = detectedOS;
    }

    lines.forEach((line, index) => {
      const trimmedLine = line.trim().toLowerCase();
      console.log(`Line ${index}: "${line}" -> "${trimmedLine}"`);
      
      // Parse different config formats with improved regex patterns
      
      // IP Address parsing - multiple formats
      if (trimmedLine.includes('ipaddr=') || trimmedLine.includes('address ') || trimmedLine.match(/^\s*address\s+[0-9]/)) {
        const ipMatch = line.match(/(?:ipaddr=|address\s+|address=)([0-9.]+)/i);
        if (ipMatch) {
          console.log("Found IP address:", ipMatch[1]);
          parsedConfig.ipAddress = ipMatch[1];
        }
      }
      
      // Netmask parsing - multiple formats including CIDR
      if (trimmedLine.includes('netmask=') || trimmedLine.includes('netmask ') || trimmedLine.includes('/')) {
        const netmaskMatch = line.match(/(?:netmask=|netmask\s+)([0-9./]+)/i) || 
                            line.match(/([0-9.]+)\/([0-9]+)/);
        if (netmaskMatch) {
          console.log("Found netmask:", netmaskMatch[1] || `/${netmaskMatch[2]}`);
          parsedConfig.netmask = netmaskMatch[1] || `/${netmaskMatch[2]}`;
        }
      }
      
      // Gateway parsing - multiple formats  
      if (trimmedLine.includes('gateway=') || trimmedLine.includes('gateway ') || trimmedLine.match(/^\s*gateway\s+[0-9]/)) {
        const gatewayMatch = line.match(/(?:gateway=|gateway\s+|gateway=)([0-9.]+)/i);
        if (gatewayMatch) {
          console.log("Found gateway:", gatewayMatch[1]);
          parsedConfig.gateway = gatewayMatch[1];
        }
      }

      // Parse netplan format (Ubuntu 18.04+)
      if (trimmedLine.includes('addresses:')) {
        const addressMatch = line.match(/addresses:\s*\[([^\]]+)\]/i);
        if (addressMatch) {
          const addr = addressMatch[1].replace(/['"]/g, '').trim();
          console.log("Found netplan address:", addr);
          if (addr.includes('/')) {
            const [ip, prefix] = addr.split('/');
            parsedConfig.ipAddress = ip.trim();
            parsedConfig.netmask = `/${prefix.trim()}`;
          } else {
            parsedConfig.ipAddress = addr;
          }
        }
      }

      // Netplan gateway
      if (trimmedLine.includes('gateway4:')) {
        const gatewayMatch = line.match(/gateway4:\s*([0-9.]+)/i);
        if (gatewayMatch) {
          console.log("Found netplan gateway:", gatewayMatch[1]);
          parsedConfig.gateway = gatewayMatch[1];
        }
      }

      // Parse interface names (eth0, ens3, etc)
      if (trimmedLine.includes('device=') || trimmedLine.includes('ifname ') || trimmedLine.match(/^[a-z0-9]+:/)) {
        const interfaceMatch = line.match(/(?:device=|ifname\s+)([a-z0-9]+)/i) ||
                               line.match(/^([a-z0-9]+):/);
        if (interfaceMatch && !interfaceMatch[1].includes('br') && !interfaceMatch[1].includes('viif') && !interfaceMatch[1].includes('bond')) {
          console.log("Found interface:", interfaceMatch[1]);
          parsedConfig.physicalInterface = interfaceMatch[1];
        }
      }

      // Parse bridge names
      if (trimmedLine.includes('bridge=') || trimmedLine.includes('bridge ')) {
        const bridgeMatch = line.match(/(?:bridge=|bridge\s+)([a-z0-9]+)/i);
        if (bridgeMatch) {
          console.log("Found bridge:", bridgeMatch[1]);
          parsedConfig.bridgeName = bridgeMatch[1];
        }
      }

      // Parse DNS servers - improved pattern
      if (trimmedLine.includes('dns') || trimmedLine.includes('nameserver')) {
        const dnsMatch = line.match(/(?:dns[_-]?nameservers?[=\s]*|addresses:\s*\[)([0-9.,\s"'\[\]]+)/i);
        if (dnsMatch) {
          const dnsServers = dnsMatch[1]
            .replace(/['"[\]]/g, '')
            .split(/[,\s]+/)
            .filter(dns => dns.match(/^[0-9.]+$/));
          if (dnsServers.length > 0) {
            console.log("Found DNS servers:", dnsServers);
            parsedConfig.dnsServers = dnsServers.join(',');
          }
        }
      }

      // Parse simple key=value format
      const keyValueMatch = line.match(/^([A-Z_]+)=(.+)$/);
      if (keyValueMatch) {
        const [, key, value] = keyValueMatch;
        const cleanValue = value.trim(); // Remove trailing spaces
        switch (key.toUpperCase()) {
          case 'IPADDR':
            console.log("Found IPADDR:", cleanValue);
            parsedConfig.ipAddress = cleanValue;
            break;
          case 'NETMASK':
            console.log("Found NETMASK:", cleanValue);
            parsedConfig.netmask = cleanValue;
            break;
          case 'GATEWAY':
            console.log("Found GATEWAY:", cleanValue);
            parsedConfig.gateway = cleanValue;
            break;
          case 'DEVICE':
            if (!cleanValue.includes('br') && !cleanValue.includes('viif')) {
              console.log("Found DEVICE:", cleanValue);
              parsedConfig.physicalInterface = cleanValue;
            }
            break;
        }
      }
    });

    console.log("Parsed configuration:", parsedConfig);

    // Apply parsed configuration
    if (Object.keys(parsedConfig).length > 0) {
      setConfig(prev => ({
        ...prev,
        ...parsedConfig
      }));

      // Clear the autofill text
      setAutoFillText("");

      toast({
        title: "Configuration Parsed",
        description: `Network configuration has been automatically filled. Found: ${Object.keys(parsedConfig).join(', ')}`,
      });
    } else {
      toast({
        title: "No Configuration Found",
        description: "Could not extract network configuration from the provided text. Please check the format.",
        variant: "destructive",
      });
    }
  };

  const generateCommands = (): void => {
    if (!validateConfig()) {
      toast({
        title: "Validation Error",
        description: "Please fix the errors in the form before generating commands.",
        variant: "destructive",
      });
      return;
    }

    const commands: GeneratedCommand[] = [];

    switch (config.osType) {
      case "centos7":
        commands.push(generateCentOS7Commands());
        break;
      case "almalinux8":
        commands.push(generateAlmaLinuxCommands());
        break;
      case "ubuntu":
        commands.push(generateUbuntuCommands());
        break;
      case "ubuntu18":
        if (config.isHetzner) {
          commands.push(generateUbuntu18HetznerCommands());
        } else {
          commands.push(generateUbuntu18Commands());
        }
        break;
      case "bond":
        commands.push(generateBondCommands());
        break;
      default:
        commands.push(generateGenericCommands());
    }

    setGeneratedCommands(commands);
    toast({
      title: "Commands Generated",
      description: "Bridge configuration commands have been generated successfully.",
    });
  };

  const generateCentOS7Commands = (): GeneratedCommand => {
    const bridgeConfig = `DEVICE=${config.bridgeName}
TYPE=Bridge
BOOTPROTO=static
IPADDR=${config.ipAddress}
NETMASK=${config.netmask}
GATEWAY=${config.gateway}
ONBOOT=yes${config.enableIpv6 ? `
IPV6INIT=yes
IPV6ADDR=${config.ipv6Address}/${config.ipv6Prefix}
IPV6_DEFAULTGW=${config.ipv6Gateway}` : ''}`;

    const interfaceConfig = `DEVICE=${config.physicalInterface}
ONBOOT=yes
BRIDGE=${config.bridgeName}`;

    return {
      title: "CentOS 7 Bridge Configuration",
      description: "Commands to create a permanent bridge on CentOS 7 without NetworkManager",
      commands: [
        "# Install bridge utilities",
        "yum install bridge-utils -y",
        "",
        "# Check if bridge module is loaded",
        "lsmod | grep bridge",
        "",
        "# Backup original interface configuration",
        `cp /etc/sysconfig/network-scripts/ifcfg-${config.physicalInterface} /etc/sysconfig/network-scripts/ifcfg-${config.physicalInterface}.bak`,
        "",
        "# Restart network service",
        "service network restart",
        "",
        "# Verify bridge is active",
        `ip addr show ${config.bridgeName}`,
        `bridge link show`
      ],
      files: [
        {
          path: `/etc/sysconfig/network-scripts/ifcfg-${config.bridgeName}`,
          content: bridgeConfig
        },
        {
          path: `/etc/sysconfig/network-scripts/ifcfg-${config.physicalInterface}`,
          content: interfaceConfig
        }
      ]
    };
  };

  const generateAlmaLinuxCommands = (): GeneratedCommand => {
    const commands = [
      "# Install bridge utilities (if not installed)",
      "dnf install bridge-utils -y",
      "",
      "# Check if bridge module is loaded",
      "lsmod | grep bridge",
      "",
      "# Create bridge using NetworkManager",
      `nmcli connection add type bridge con-name ${config.bridgeName} ifname ${config.bridgeName}`,
    ];

    // Always add STP command as per documentation
    commands.push(`nmcli connection modify ${config.bridgeName} bridge.stp no`);

    commands.push(
      `nmcli connection modify ${config.bridgeName} ipv4.addresses '${config.ipAddress}/${config.netmask.split('/')[1] || '24'}' ipv4.gateway '${config.gateway}' ipv4.dns '${config.dnsServers.split(',')[0]}' ipv4.method manual`
    );

    if (config.enableIpv6) {
      commands.push(
        `nmcli connection modify ${config.bridgeName} ipv6.addresses '${config.ipv6Address}/${config.ipv6Prefix}' ipv6.gateway '${config.ipv6Gateway}' ipv6.dns '2001:4860:4860::8888' ipv6.method manual`
      );
    }

    commands.push(
      `nmcli connection modify ${config.physicalInterface} master ${config.bridgeName}`,
      `nmcli connection modify ${config.bridgeName} connection.autoconnect-slaves 1`,
      `nmcli connection up ${config.bridgeName}`,
      `nmcli connection up ${config.physicalInterface}`,
      "",
      "# Verify bridge configuration",
      `nmcli connection show ${config.bridgeName}`,
      `ip addr show ${config.bridgeName}`,
      "bridge link show"
    );

    return {
      title: "AlmaLinux 8.x/9.x Bridge Configuration",
      description: "Commands to create a bridge using NetworkManager on AlmaLinux",
      commands
    };
  };

  const generateUbuntuCommands = (): GeneratedCommand => {
    const interfacesConfig = `# The loopback network interface
auto lo
iface lo inet loopback

# Bridge for ${config.physicalInterface}
auto ${config.bridgeName}
iface ${config.bridgeName} inet static
address ${config.ipAddress}
netmask ${config.netmask}
gateway ${config.gateway}
dns-nameservers ${config.dnsServers.replace(',', ' ')}
bridge_ports ${config.physicalInterface}
bridge_stp ${config.enableStp ? 'on' : 'off'}
bridge_fd 0
bridge_maxwait 0${config.mtu !== '1500' ? `
bridge_mtu ${config.mtu}` : ''}${config.enableIpv6 ? `

iface ${config.bridgeName} inet6 static
pre-up modprobe ipv6
address ${config.ipv6Address}
netmask ${config.ipv6Prefix}
gateway ${config.ipv6Gateway}` : ''}`;

    return {
      title: "Ubuntu Bridge Configuration",
      description: "Configuration for Ubuntu using /etc/network/interfaces",
      commands: [
        "# Install bridge utilities",
        "apt-get update && apt-get install bridge-utils -y",
        "",
        "# Backup original interfaces file",
        "cp /etc/network/interfaces /etc/network/interfaces.bak",
        "",
        config.enableIpv6 ? "# Enable IPv6" : "",
        config.enableIpv6 ? "echo 'net.ipv6.conf.default.disable_ipv6 = 0' >> /etc/sysctl.conf" : "",
        config.enableIpv6 ? "echo 'net.ipv6.conf.all.disable_ipv6 = 0' >> /etc/sysctl.conf" : "",
        config.enableIpv6 ? "sysctl -p" : "",
        config.enableIpv6 ? "" : "",
        "# Restart networking",
        "/etc/init.d/networking restart",
        "",
        "# Verify bridge configuration",
        `ip addr show ${config.bridgeName}`,
        "bridge link show"
      ].filter(cmd => cmd !== ""),
      files: [
        {
          path: "/etc/network/interfaces",
          content: interfacesConfig
        }
      ]
    };
  };

  const generateUbuntu18HetznerCommands = (): GeneratedCommand => {
    const netplanConfig = `network:
  version: 2
  renderer: networkd
  ethernets:
    ${config.physicalInterface}:
      dhcp4: no
      dhcp6: no
  bridges:
    ${config.bridgeName}:
      interfaces: [${config.physicalInterface}]
      addresses: [${config.ipAddress}/${config.netmask.split('/')[1] || '24'}${config.enableIpv6 ? `,
        "${config.ipv6Address}/${config.ipv6Prefix}"` : ''}]
      gateway4: ${config.gateway}${config.enableIpv6 && config.ipv6Gateway ? `
      gateway6: ${config.ipv6Gateway}` : ''}
      nameservers:
        addresses: [${config.dnsServers.split(',').map(dns => `"${dns.trim()}"`).join(', ')}${config.enableIpv6 ? `, "2001:4860:4860::8888", "2001:4860:4860::8844"` : ''}]
      dhcp4: no
      dhcp6: no${config.enableStp ? `
      parameters:
        stp: false` : ''}`;

    return {
      title: "Ubuntu 18.04+ Bridge Configuration (Hetzner Method)",
      description: "Configuration for Ubuntu 18.04+ using Netplan specifically for Hetzner servers",
      commands: [
        "# Install bridge utilities",
        "apt-get update && apt-get install bridge-utils -y",
        "",
        "# Backup existing netplan configuration",
        "cp /etc/netplan/*.yaml /etc/netplan/backup-$(date +%Y%m%d).yaml",
        "",
        "# Remove existing interface configuration (Hetzner specific)",
        "rm -f /etc/netplan/50-cloud-init.yaml",
        "",
        "# Apply netplan configuration",
        "netplan apply",
        "",
        "# Verify bridge configuration",
        `ip addr show ${config.bridgeName}`,
        "bridge link show"
      ],
      files: [
        {
          path: "/etc/netplan/01-netcfg.yaml",
          content: netplanConfig
        }
      ]
    };
  };

  const generateUbuntu18Commands = (): GeneratedCommand => {
    const netplanConfig = `network:
  version: 2
  renderer: networkd
  ethernets:
    ${config.physicalInterface}:
      dhcp4: no
      dhcp6: no
  bridges:
    ${config.bridgeName}:
      interfaces: [${config.physicalInterface}]
      addresses: [${config.ipAddress}/${config.netmask.split('/')[1] || '24'}${config.enableIpv6 ? `,
        "${config.ipv6Address}/${config.ipv6Prefix}"` : ''}]
      gateway4: ${config.gateway}${config.enableIpv6 && config.ipv6Gateway ? `
      gateway6: ${config.ipv6Gateway}` : ''}
      nameservers:
        addresses: [${config.dnsServers.split(',').map(dns => `"${dns.trim()}"`).join(', ')}${config.enableIpv6 ? `, "2001:4860:4860::8888", "2001:4860:4860::8844"` : ''}]
      dhcp4: no
      dhcp6: no${config.enableStp ? `
      parameters:
        stp: false` : ''}`;

    return {
      title: "Ubuntu 18.04+ Bridge Configuration (Standard Method)",
      description: "Configuration for Ubuntu 18.04+ using Netplan for standard servers",
      commands: [
        "# Install bridge utilities",
        "apt-get update && apt-get install bridge-utils -y",
        "",
        "# Backup existing netplan configuration",
        "cp /etc/netplan/*.yaml /etc/netplan/backup-$(date +%Y%m%d).yaml",
        "",
        "# Apply netplan configuration",
        "netplan apply",
        "",
        "# Verify bridge configuration",
        `ip addr show ${config.bridgeName}`,
        "bridge link show"
      ],
      files: [
        {
          path: "/etc/netplan/01-netcfg.yaml",
          content: netplanConfig
        }
      ]
    };
  };

  const generateBondCommands = (): GeneratedCommand => {
    const bondConfig = `# Bond configuration for high availability
DEVICE=bond0
TYPE=Bond
BONDING_MASTER=yes
BOOTPROTO=static
IPADDR=${config.ipAddress}
NETMASK=${config.netmask}
GATEWAY=${config.gateway}
ONBOOT=yes
BONDING_OPTS="mode=active-backup miimon=100"${config.enableIpv6 ? `
IPV6INIT=yes
IPV6ADDR=${config.ipv6Address}/${config.ipv6Prefix}
IPV6_DEFAULTGW=${config.ipv6Gateway}` : ''}`;

    const bridgeOnBondConfig = `# Bridge on top of bond
DEVICE=${config.bridgeName}
TYPE=Bridge
BOOTPROTO=static
IPADDR=${config.ipAddress}
NETMASK=${config.netmask}
GATEWAY=${config.gateway}
ONBOOT=yes${config.enableIpv6 ? `
IPV6INIT=yes
IPV6ADDR=${config.ipv6Address}/${config.ipv6Prefix}
IPV6_DEFAULTGW=${config.ipv6Gateway}` : ''}`;

    const slaveConfig = `# Slave interface configuration
DEVICE=${config.physicalInterface}
TYPE=Ethernet
ONBOOT=yes
MASTER=bond0
SLAVE=yes`;

    const bondBridgeConfig = `# Bond as bridge member
DEVICE=bond0
ONBOOT=yes
BRIDGE=${config.bridgeName}`;

    return {
      title: "Bond Server Bridge Configuration",
      description: "High availability bond configuration with bridge for redundant network setup",
      commands: [
        "# Install bonding and bridge utilities",
        "modprobe bonding",
        "modprobe bridge",
        "",
        "# For RHEL/CentOS/AlmaLinux:",
        "yum install bridge-utils -y || dnf install bridge-utils -y",
        "",
        "# For Ubuntu/Debian:",
        "# apt-get update && apt-get install bridge-utils ifenslave -y",
        "",
        "# Load bonding module at boot",
        "echo 'bonding' >> /etc/modules-load.d/bonding.conf",
        "",
        "# Backup original interface configurations",
        `cp /etc/sysconfig/network-scripts/ifcfg-${config.physicalInterface} /etc/sysconfig/network-scripts/ifcfg-${config.physicalInterface}.bak 2>/dev/null || echo "No existing config to backup"`,
        "",
        "# Restart network service",
        "systemctl restart network || systemctl restart NetworkManager",
        "",
        "# Verify bond and bridge status",
        "cat /proc/net/bonding/bond0",
        `ip addr show ${config.bridgeName}`,
        "bridge link show",
        "",
        "# Check bond status",
        "ip link show bond0",
        "ip link show | grep -E '(bond0|${config.bridgeName}|${config.physicalInterface})'"
      ],
      files: [
        {
          path: "/etc/sysconfig/network-scripts/ifcfg-bond0",
          content: bondConfig
        },
        {
          path: `/etc/sysconfig/network-scripts/ifcfg-${config.bridgeName}`,
          content: bridgeOnBondConfig
        },
        {
          path: `/etc/sysconfig/network-scripts/ifcfg-${config.physicalInterface}`,
          content: slaveConfig
        }
      ]
    };
  };

  const generateGenericCommands = (): GeneratedCommand => {
    return {
      title: "Generic Linux Bridge Configuration",
      description: "Manual bridge configuration commands for any Linux distribution",
      commands: [
        "# Install bridge utilities (distribution specific)",
        "# For Debian/Ubuntu: apt-get install bridge-utils",
        "# For RHEL/CentOS: yum install bridge-utils",
        "# For openSUSE: zypper install bridge-utils",
        "",
        "# Create bridge",
        `ip link add name ${config.bridgeName} type bridge`,
        `ip link set ${config.bridgeName} up`,
        "",
        "# Add physical interface to bridge",
        `ip link set ${config.physicalInterface} master ${config.bridgeName}`,
        "",
        "# Configure IP address",
        `ip addr add ${config.ipAddress}/${config.netmask.split('/')[1] || '24'} dev ${config.bridgeName}`,
        "",
        "# Add default route",
        `ip route add default via ${config.gateway} dev ${config.bridgeName}`,
        "",
        config.enableIpv6 ? `# Configure IPv6 address` : "",
        config.enableIpv6 ? `ip -6 addr add ${config.ipv6Address}/${config.ipv6Prefix} dev ${config.bridgeName}` : "",
        config.enableIpv6 ? `ip -6 route add default via ${config.ipv6Gateway} dev ${config.bridgeName}` : "",
        config.enableIpv6 ? "" : "",
        "# Verify bridge configuration",
        `ip addr show ${config.bridgeName}`,
        "bridge link show"
      ].filter(cmd => cmd !== "")
    };
  };

  const copyToClipboard = async (text: string): Promise<void> => {
    try {
      await navigator.clipboard.writeText(text);
      toast({
        title: "Copied to clipboard",
        description: "Commands have been copied to your clipboard.",
      });
    } catch (err) {
      toast({
        title: "Copy failed",
        description: "Failed to copy to clipboard. Please copy manually.",
        variant: "destructive",
      });
    }
  };

  const downloadScript = (command: GeneratedCommand): void => {
    const scriptContent = `#!/bin/bash
# ${command.title}
# ${command.description}

${command.commands.join('\n')}
`;

    const blob = new Blob([scriptContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `bridge-setup-${config.osType}.sh`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    toast({
      title: "Script Downloaded",
      description: "Bridge setup script has been downloaded.",
    });
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-card to-secondary/20 p-6">
      <div className="max-w-7xl mx-auto space-y-10">
        {/* Header */}
        <div className="text-center space-y-6 py-12">
          <div className="flex items-center justify-center gap-4 mb-6">
            <div className="p-3 rounded-xl bg-gradient-primary shadow-glow">
              <Network className="h-12 w-12 text-white" />
            </div>
            <div>
              <h1 className="text-5xl font-bold bg-gradient-primary bg-clip-text text-transparent">
                Bridge Configuration Generator
              </h1>
              <div className="h-1 w-32 bg-gradient-primary rounded-full mx-auto mt-2"></div>
            </div>
          </div>
          <p className="text-xl text-muted-foreground max-w-4xl mx-auto leading-relaxed">
            Professional network bridge configuration tool for enterprise server infrastructure
          </p>
        </div>

        {/* Main Configuration Form */}
        <Card className="backdrop-blur-sm bg-gradient-card border-border/50 shadow-professional hover:shadow-lg transition-all duration-500">
          <CardHeader className="pb-8 border-b border-border/50">
            <div className="flex items-center justify-between">
              <div className="space-y-3">
                <CardTitle className="text-3xl flex items-center gap-3 font-semibold">
                  <div className="p-2 rounded-lg bg-primary/10">
                    <Network className="h-7 w-7 text-primary" />
                  </div>
                  Bridge Configuration
                </CardTitle>
                <CardDescription className="text-lg text-muted-foreground">
                  Configure your network bridge settings with precision and control
                </CardDescription>
              </div>
              {config.isHetzner && (
                <Badge variant="secondary" className="text-sm px-4 py-2 rounded-full shadow-sm">
                  <AlertTriangle className="h-4 w-4 mr-2" />
                  Hetzner Server Detected
                </Badge>
              )}
            </div>
          </CardHeader>

          <CardContent className="space-y-8 pt-8">
            {/* Auto-fill from config */}
            <div className="space-y-4 p-6 rounded-xl bg-accent/30 border border-accent/40">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-info/10">
                  <Info className="h-5 w-5 text-info" />
                </div>
                <div>
                  <Label htmlFor="autoFill" className="text-lg font-semibold">
                    Smart Configuration Parser
                  </Label>
                  <p className="text-sm text-muted-foreground mt-1">
                    Automatically extract settings from your existing network configuration
                  </p>
                </div>
              </div>
              <div className="space-y-3">
                <Textarea
                  id="autoFill"
                  placeholder="Paste your current network configuration file content here (e.g., /etc/network/interfaces, ifcfg-eth0, netplan yaml)..."
                  value={autoFillText}
                  onChange={(e) => setAutoFillText(e.target.value)}
                  className="min-h-[120px] font-mono text-sm bg-background/50 border-border/60 focus:border-primary/60 transition-colors"
                />
                <Button
                  onClick={() => parseNetworkConfig(autoFillText)}
                  disabled={!autoFillText.trim()}
                  variant="secondary"
                  className="w-full bg-primary/5 hover:bg-primary/10 border-primary/20"
                >
                  <Info className="h-4 w-4 mr-2" />
                  Parse Configuration
                </Button>
              </div>
            </div>

            <Separator className="my-8 bg-gradient-to-r from-transparent via-border to-transparent h-px" />

            {/* Form content with improved spacing and design */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              {/* Operating System */}
              <div className="space-y-4">
                <Label className="text-lg font-semibold flex items-center gap-2">
                  Operating System
                  <span className="text-destructive">*</span>
                </Label>
                <Select value={config.osType} onValueChange={(value) => setConfig(prev => ({ ...prev, osType: value }))}>
                  <SelectTrigger className={`h-12 text-base ${errors.osType ? "border-destructive" : "border-border hover:border-primary/50"} transition-colors`}>
                    <SelectValue placeholder="Select your operating system" />
                  </SelectTrigger>
                  <SelectContent className="bg-popover/95 backdrop-blur-sm">
                    <SelectItem value="centos7" className="text-base py-3">CentOS 7</SelectItem>
                    <SelectItem value="almalinux8" className="text-base py-3">AlmaLinux 8.x/9.x</SelectItem>
                    <SelectItem value="ubuntu" className="text-base py-3">Ubuntu 16.04/20.04</SelectItem>
                    <SelectItem value="ubuntu18" className="text-base py-3">Ubuntu 18.04+</SelectItem>
                    <SelectItem value="bond" className="text-base py-3">Bond Server Configuration</SelectItem>
                    <SelectItem value="generic" className="text-base py-3">Generic Linux</SelectItem>
                  </SelectContent>
                </Select>
                {errors.osType && (
                  <p className="text-sm text-destructive flex items-center gap-2 bg-destructive/10 p-2 rounded-lg">
                    <AlertTriangle className="h-4 w-4" />
                    {errors.osType}
                  </p>
                )}
              </div>

              {/* Bridge Name */}
              <div className="space-y-4">
                <Label className="text-lg font-semibold flex items-center gap-2">
                  Bridge Name
                  <span className="text-destructive">*</span>
                </Label>
                <Input
                  value={config.bridgeName}
                  onChange={(e) => setConfig(prev => ({ ...prev, bridgeName: e.target.value }))}
                  placeholder="viifbr0"
                  className={`h-12 text-base ${errors.bridgeName ? "border-destructive" : "border-border hover:border-primary/50"} transition-colors bg-background/50`}
                />
                {errors.bridgeName && (
                  <p className="text-sm text-destructive flex items-center gap-2 bg-destructive/10 p-2 rounded-lg">
                    <AlertTriangle className="h-4 w-4" />
                    {errors.bridgeName}
                  </p>
                )}
              </div>
            </div>

            {/* Network Configuration with improved styling */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 pt-4">
              {/* IP Address */}
              <div className="space-y-4">
                <Label className="text-lg font-semibold flex items-center gap-3">
                  IP Address
                  <span className="text-destructive">*</span>
                  {config.isHetzner && (
                    <Badge variant="outline" className="text-xs bg-warning/10 text-warning border-warning/30">
                      Hetzner Detected
                    </Badge>
                  )}
                </Label>
                <Input
                  value={config.ipAddress}
                  onChange={(e) => {
                    const newIP = e.target.value;
                    const isHetznerIP = detectHetzner(newIP);
                    setConfig(prev => ({ 
                      ...prev, 
                      ipAddress: newIP, 
                      isHetzner: isHetznerIP 
                    }));
                  }}
                  placeholder="192.168.1.100"
                  className={`h-12 text-base ${errors.ipAddress ? "border-destructive" : "border-border hover:border-primary/50"} transition-colors bg-background/50`}
                />
                {errors.ipAddress && (
                  <p className="text-sm text-destructive flex items-center gap-2 bg-destructive/10 p-2 rounded-lg">
                    <AlertTriangle className="h-4 w-4" />
                    {errors.ipAddress}
                  </p>
                )}
              </div>

              {/* Netmask */}
              <div className="space-y-4">
                <Label className="text-lg font-semibold flex items-center gap-2">
                  Netmask
                  <span className="text-destructive">*</span>
                </Label>
                <Select value={config.netmask} onValueChange={(value) => setConfig(prev => ({ ...prev, netmask: value }))}>
                  <SelectTrigger className={`h-12 text-base ${errors.netmask ? "border-destructive" : "border-border hover:border-primary/50"} transition-colors`}>
                    <SelectValue placeholder="Select netmask" />
                  </SelectTrigger>
                  <SelectContent className="bg-popover/95 backdrop-blur-sm max-h-60 overflow-auto">
                    {getNetmaskOptions().map(option => (
                      <SelectItem key={option.value} value={option.value} className="text-base py-3">
                        {option.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {errors.netmask && (
                  <p className="text-sm text-destructive flex items-center gap-2 bg-destructive/10 p-2 rounded-lg">
                    <AlertTriangle className="h-4 w-4" />
                    {errors.netmask}
                  </p>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 pt-4">
              {/* Gateway */}
              <div className="space-y-4">
                <Label className="text-lg font-semibold flex items-center gap-2">
                  Gateway
                  <span className="text-destructive">*</span>
                </Label>
                <Input
                  value={config.gateway}
                  onChange={(e) => setConfig(prev => ({ ...prev, gateway: e.target.value }))}
                  placeholder="192.168.1.1"
                  className={`h-12 text-base ${errors.gateway ? "border-destructive" : "border-border hover:border-primary/50"} transition-colors bg-background/50`}
                />
                {errors.gateway && (
                  <p className="text-sm text-destructive flex items-center gap-2 bg-destructive/10 p-2 rounded-lg">
                    <AlertTriangle className="h-4 w-4" />
                    {errors.gateway}
                  </p>
                )}
              </div>

              {/* Physical Interface */}
              <div className="space-y-4">
                <Label className="text-lg font-semibold flex items-center gap-2">
                  Physical Interface
                  <span className="text-destructive">*</span>
                </Label>
                <Input
                  value={config.physicalInterface}
                  onChange={(e) => setConfig(prev => ({ ...prev, physicalInterface: e.target.value }))}
                  placeholder="eth0"
                  className={`h-12 text-base ${errors.physicalInterface ? "border-destructive" : "border-border hover:border-primary/50"} transition-colors bg-background/50`}
                />
                {errors.physicalInterface && (
                  <p className="text-sm text-destructive flex items-center gap-2 bg-destructive/10 p-2 rounded-lg">
                    <AlertTriangle className="h-4 w-4" />
                    {errors.physicalInterface}
                  </p>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 pt-4">
              {/* Enable STP */}
              <div className="flex items-center space-x-4">
                <Switch
                  id="enableStp"
                  checked={config.enableStp}
                  onCheckedChange={(checked) => setConfig(prev => ({ ...prev, enableStp: checked }))}
                />
                <Label htmlFor="enableStp" className="text-lg font-semibold">
                  Enable STP (Spanning Tree Protocol)
                </Label>
              </div>

              {/* MTU */}
              <div className="space-y-4">
                <Label className="text-lg font-semibold flex items-center gap-2">
                  MTU
                </Label>
                <Input
                  type="number"
                  min={576}
                  max={9000}
                  value={config.mtu}
                  onChange={(e) => setConfig(prev => ({ ...prev, mtu: e.target.value }))}
                  placeholder="1500"
                  className="h-12 text-base border-border hover:border-primary/50 transition-colors bg-background/50"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 pt-4">
              {/* Enable IPv6 */}
              <div className="flex items-center space-x-4">
                <Switch
                  id="enableIpv6"
                  checked={config.enableIpv6}
                  onCheckedChange={(checked) => setConfig(prev => ({ ...prev, enableIpv6: checked }))}
                />
                <Label htmlFor="enableIpv6" className="text-lg font-semibold">
                  Enable IPv6
                </Label>
              </div>

              {/* DNS Servers */}
              <div className="space-y-4">
                <Label className="text-lg font-semibold flex items-center gap-2">
                  DNS Servers
                </Label>
                <Input
                  value={config.dnsServers}
                  onChange={(e) => setConfig(prev => ({ ...prev, dnsServers: e.target.value }))}
                  placeholder="8.8.8.8,8.8.4.4"
                  className="h-12 text-base border-border hover:border-primary/50 transition-colors bg-background/50"
                />
              </div>
            </div>

            {config.enableIpv6 && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 pt-4">
                {/* IPv6 Address */}
                <div className="space-y-4">
                  <Label className="text-lg font-semibold flex items-center gap-2">
                    IPv6 Address
                    <span className="text-destructive">*</span>
                  </Label>
                  <Input
                    value={config.ipv6Address}
                    onChange={(e) => setConfig(prev => ({ ...prev, ipv6Address: e.target.value }))}
                    placeholder="2001:db8::1"
                    className={`h-12 text-base ${errors.ipv6Address ? "border-destructive" : "border-border hover:border-primary/50"} transition-colors bg-background/50`}
                  />
                  {errors.ipv6Address && (
                    <p className="text-sm text-destructive flex items-center gap-2 bg-destructive/10 p-2 rounded-lg">
                      <AlertTriangle className="h-4 w-4" />
                      {errors.ipv6Address}
                    </p>
                  )}
                </div>

                {/* IPv6 Gateway */}
                <div className="space-y-4">
                  <Label className="text-lg font-semibold flex items-center gap-2">
                    IPv6 Gateway
                    <span className="text-destructive">*</span>
                  </Label>
                  <Input
                    value={config.ipv6Gateway}
                    onChange={(e) => setConfig(prev => ({ ...prev, ipv6Gateway: e.target.value }))}
                    placeholder="2001:db8::fffe"
                    className={`h-12 text-base ${errors.ipv6Gateway ? "border-destructive" : "border-border hover:border-primary/50"} transition-colors bg-background/50`}
                  />
                  {errors.ipv6Gateway && (
                    <p className="text-sm text-destructive flex items-center gap-2 bg-destructive/10 p-2 rounded-lg">
                      <AlertTriangle className="h-4 w-4" />
                      {errors.ipv6Gateway}
                    </p>
                  )}
                </div>
              </div>
            )}

            {/* Generate Button */}
            <div className="flex justify-center pt-8">
              <Button
                onClick={generateCommands}
                size="lg"
                className="px-12 py-4 text-lg font-semibold min-w-[280px] bg-gradient-primary hover:opacity-95 shadow-professional hover:shadow-glow transition-all duration-500 transform hover:scale-105"
              >
                <Network className="h-6 w-6 mr-3" />
                Generate Bridge Commands
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Generated Commands Display */}
        {generatedCommands.length > 0 && (
          <div className="space-y-8">
            {generatedCommands.map((command, index) => (
              <Card key={index} className="backdrop-blur-sm bg-gradient-card border-border/60 shadow-professional hover:shadow-lg transition-all duration-500">
                <CardHeader className="pb-6 border-b border-border/50">
                  <div className="flex items-center justify-between">
                    <div className="space-y-3">
                      <CardTitle className="text-2xl flex items-center gap-3 font-semibold">
                        <div className="p-2 rounded-lg bg-success/10">
                          <CheckCircle className="h-6 w-6 text-success" />
                        </div>
                        {command.title}
                      </CardTitle>
                      <CardDescription className="text-base text-muted-foreground">
                        {command.description}
                      </CardDescription>
                    </div>
                    <div className="flex gap-3">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => copyToClipboard(command.commands.join('\n'))}
                        className="flex items-center gap-2 px-4 py-2 bg-background/50 hover:bg-primary/5 border-primary/20 transition-colors"
                      >
                        <Copy className="h-4 w-4" />
                        Copy Commands
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => downloadScript(command)}
                        className="flex items-center gap-2 px-4 py-2 bg-background/50 hover:bg-success/5 border-success/20 transition-colors"
                      >
                        <Download className="h-4 w-4" />
                        Download Script
                      </Button>
                    </div>
                  </div>
                </CardHeader>

                <CardContent className="space-y-6">
                  {/* Commands */}
                  <div className="space-y-3">
                    <h4 className="text-lg font-semibold">Commands</h4>
                    <div className="bg-muted/30 rounded-lg p-4 border">
                      <pre className="text-sm font-mono whitespace-pre-wrap text-foreground/90">
                        {command.commands.join('\n')}
                      </pre>
                    </div>
                  </div>

                  {/* Files */}
                  {command.files && command.files.length > 0 && (
                    <div className="space-y-4">
                      <h4 className="text-lg font-semibold">Configuration Files</h4>
                      {command.files.map((file, fileIndex) => (
                        <div key={fileIndex} className="space-y-2">
                          <div className="flex items-center justify-between">
                            <Label className="text-base font-medium">{file.path}</Label>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => copyToClipboard(file.content)}
                              className="text-xs"
                            >
                              <Copy className="h-3 w-3 mr-1" />
                              Copy
                            </Button>
                          </div>
                          <div className="bg-muted/30 rounded-lg p-4 border">
                            <pre className="text-sm font-mono whitespace-pre-wrap text-foreground/90">
                              {file.content}
                            </pre>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
