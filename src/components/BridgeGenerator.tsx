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
    mtu: "1500"
  });

  const [generatedCommands, setGeneratedCommands] = useState<GeneratedCommand[]>([]);
  const [errors, setErrors] = useState<Record<string, string>>({});

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
    return validateIP(netmask);
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
        commands.push(generateUbuntu18Commands());
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

    if (config.enableStp) {
      commands.push(`nmcli connection modify ${config.bridgeName} bridge.stp no`);
    }

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

  const generateUbuntu18Commands = (): GeneratedCommand => {
    const netplanConfig = `network:
  version: 2
  renderer: networkd
  ethernets:
    ${config.physicalInterface}:
      dhcp4: no
  bridges:
    ${config.bridgeName}:
      addresses:
        - ${config.ipAddress}/${config.netmask.split('/')[1] || '24'}${config.enableIpv6 ? `
        - "${config.ipv6Address}/${config.ipv6Prefix}"` : ''}
      interfaces: [ ${config.physicalInterface} ]${config.gateway ? `
      routes:
        - to: 0.0.0.0/0
          via: ${config.gateway}` : ''}${config.enableIpv6 && config.ipv6Gateway ? `
      gateway6: ${config.ipv6Gateway}` : ''}
      nameservers:
         addresses:${config.dnsServers.split(',').map(dns => `
           - ${dns.trim()}`).join('')}${config.enableIpv6 ? `
           - 2001:4860:4860::8888
           - 2001:4860:4860::8844` : ''}${config.enableStp ? `
      parameters:
        stp: false` : ''}`;

    return {
      title: "Ubuntu 18.04+ Bridge Configuration (Netplan)",
      description: "Configuration for Ubuntu 18.04+ using Netplan",
      commands: [
        "# Install bridge utilities",
        "apt-get update && apt-get install bridge-utils -y",
        "",
        "# Backup existing netplan configuration",
        "cp /etc/netplan/*.yaml /etc/netplan/backup-$(date +%Y%m%d).yaml",
        "",
        "# Apply the new configuration",
        "netplan apply",
        "",
        "# Verify bridge configuration",
        `ip addr show ${config.bridgeName}`,
        "bridge link show",
        "netplan status"
      ],
      files: [
        {
          path: "/etc/netplan/01-netcfg.yaml",
          content: netplanConfig
        }
      ]
    };
  };

  const generateGenericCommands = (): GeneratedCommand => {
    return {
      title: "Generic Bridge Commands",
      description: "Generic commands using ip and brctl utilities",
      commands: [
        "# Create bridge interface",
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
        config.enableIpv6 ? "# Configure IPv6" : "",
        config.enableIpv6 ? `ip -6 addr add ${config.ipv6Address}/${config.ipv6Prefix} dev ${config.bridgeName}` : "",
        config.enableIpv6 ? `ip -6 route add default via ${config.ipv6Gateway} dev ${config.bridgeName}` : "",
        config.enableIpv6 ? "" : "",
        "# Verify configuration",
        `ip addr show ${config.bridgeName}`,
        "bridge link show"
      ].filter(cmd => cmd !== "")
    };
  };

  const copyToClipboard = (text: string): void => {
    navigator.clipboard.writeText(text).then(() => {
      toast({
        title: "Copied to Clipboard",
        description: "Commands have been copied to your clipboard.",
      });
    });
  };

  const downloadScript = (commands: GeneratedCommand): void => {
    const scriptContent = commands.commands.join('\n');
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
      description: "The bridge setup script has been downloaded.",
    });
  };

  return (
    <div className="container mx-auto px-4 py-8 space-y-8">
      {/* Header */}
      <div className="text-center space-y-4">
        <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-primary rounded-full mb-4 shadow-glow">
          <Network className="w-8 h-8 text-primary-foreground" />
        </div>
        <h1 className="text-4xl font-bold bg-gradient-hero bg-clip-text text-transparent">
          Bridge Configuration Generator
        </h1>
        <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
          Generate network bridge configuration commands for KVM virtualization based on Virtualizor documentation
        </p>
      </div>

      <div className="grid lg:grid-cols-2 gap-8">
        {/* Configuration Form */}
        <Card className="shadow-custom-lg">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Network className="w-5 h-5 text-primary" />
              Network Configuration
            </CardTitle>
            <CardDescription>
              Configure your server's network settings to generate the appropriate bridge commands
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Operating System */}
            <div className="space-y-2">
              <Label htmlFor="osType">Operating System *</Label>
              <Select value={config.osType} onValueChange={(value) => setConfig(prev => ({ ...prev, osType: value }))}>
                <SelectTrigger className={errors.osType ? "border-destructive" : ""}>
                  <SelectValue placeholder="Select your operating system" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="centos7">CentOS 7 (Without NetworkManager)</SelectItem>
                  <SelectItem value="almalinux8">AlmaLinux 8.x / 9.x</SelectItem>
                  <SelectItem value="ubuntu">Ubuntu (Legacy interfaces)</SelectItem>
                  <SelectItem value="ubuntu18">Ubuntu 18.04+ (Netplan)</SelectItem>
                  <SelectItem value="generic">Generic (ip commands)</SelectItem>
                </SelectContent>
              </Select>
              {errors.osType && <p className="text-sm text-destructive">{errors.osType}</p>}
            </div>

            {/* Basic Network Settings */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="ipAddress">IP Address *</Label>
                <Input
                  id="ipAddress"
                  placeholder="192.168.1.10"
                  value={config.ipAddress}
                  onChange={(e) => setConfig(prev => ({ ...prev, ipAddress: e.target.value }))}
                  className={errors.ipAddress ? "border-destructive" : ""}
                />
                {errors.ipAddress && <p className="text-sm text-destructive">{errors.ipAddress}</p>}
              </div>

              <div className="space-y-2">
                <Label htmlFor="netmask">Netmask *</Label>
                <Input
                  id="netmask"
                  placeholder="255.255.255.0 or /24"
                  value={config.netmask}
                  onChange={(e) => setConfig(prev => ({ ...prev, netmask: e.target.value }))}
                  className={errors.netmask ? "border-destructive" : ""}
                />
                {errors.netmask && <p className="text-sm text-destructive">{errors.netmask}</p>}
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="gateway">Gateway *</Label>
              <Input
                id="gateway"
                placeholder="192.168.1.1"
                value={config.gateway}
                onChange={(e) => setConfig(prev => ({ ...prev, gateway: e.target.value }))}
                className={errors.gateway ? "border-destructive" : ""}
              />
              {errors.gateway && <p className="text-sm text-destructive">{errors.gateway}</p>}
            </div>

            {/* Bridge Settings */}
            <Separator />
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="bridgeName">Bridge Name *</Label>
                <Input
                  id="bridgeName"
                  placeholder="viifbr0"
                  value={config.bridgeName}
                  onChange={(e) => setConfig(prev => ({ ...prev, bridgeName: e.target.value }))}
                  className={errors.bridgeName ? "border-destructive" : ""}
                />
                {errors.bridgeName && <p className="text-sm text-destructive">{errors.bridgeName}</p>}
              </div>

              <div className="space-y-2">
                <Label htmlFor="physicalInterface">Physical Interface *</Label>
                <Input
                  id="physicalInterface"
                  placeholder="eth0, ens3, etc."
                  value={config.physicalInterface}
                  onChange={(e) => setConfig(prev => ({ ...prev, physicalInterface: e.target.value }))}
                  className={errors.physicalInterface ? "border-destructive" : ""}
                />
                {errors.physicalInterface && <p className="text-sm text-destructive">{errors.physicalInterface}</p>}
              </div>
            </div>

            {/* Advanced Options */}
            <Separator />
            <div className="space-y-4">
              <div className="flex items-center space-x-2">
                <Switch
                  id="enableIpv6"
                  checked={config.enableIpv6}
                  onCheckedChange={(checked) => setConfig(prev => ({ ...prev, enableIpv6: checked }))}
                />
                <Label htmlFor="enableIpv6">Enable IPv6 Configuration</Label>
              </div>

              {config.enableIpv6 && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pl-6 border-l-2 border-accent">
                  <div className="space-y-2">
                    <Label htmlFor="ipv6Address">IPv6 Address</Label>
                    <Input
                      id="ipv6Address"
                      placeholder="2001:db8::1"
                      value={config.ipv6Address}
                      onChange={(e) => setConfig(prev => ({ ...prev, ipv6Address: e.target.value }))}
                      className={errors.ipv6Address ? "border-destructive" : ""}
                    />
                    {errors.ipv6Address && <p className="text-sm text-destructive">{errors.ipv6Address}</p>}
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="ipv6Gateway">IPv6 Gateway</Label>
                    <Input
                      id="ipv6Gateway"
                      placeholder="2001:db8::1"
                      value={config.ipv6Gateway}
                      onChange={(e) => setConfig(prev => ({ ...prev, ipv6Gateway: e.target.value }))}
                      className={errors.ipv6Gateway ? "border-destructive" : ""}
                    />
                    {errors.ipv6Gateway && <p className="text-sm text-destructive">{errors.ipv6Gateway}</p>}
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="ipv6Prefix">IPv6 Prefix Length</Label>
                    <Input
                      id="ipv6Prefix"
                      placeholder="64"
                      value={config.ipv6Prefix}
                      onChange={(e) => setConfig(prev => ({ ...prev, ipv6Prefix: e.target.value }))}
                    />
                  </div>
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="dnsServers">DNS Servers</Label>
                <Input
                  id="dnsServers"
                  placeholder="8.8.8.8,8.8.4.4"
                  value={config.dnsServers}
                  onChange={(e) => setConfig(prev => ({ ...prev, dnsServers: e.target.value }))}
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="mtu">MTU Size</Label>
                  <Input
                    id="mtu"
                    placeholder="1500"
                    value={config.mtu}
                    onChange={(e) => setConfig(prev => ({ ...prev, mtu: e.target.value }))}
                  />
                </div>

                <div className="flex items-center space-x-2 pt-6">
                  <Switch
                    id="enableStp"
                    checked={config.enableStp}
                    onCheckedChange={(checked) => setConfig(prev => ({ ...prev, enableStp: checked }))}
                  />
                  <Label htmlFor="enableStp">Enable STP</Label>
                </div>
              </div>
            </div>

            <Button 
              onClick={generateCommands} 
              className="w-full bg-gradient-primary hover:opacity-90 transition-opacity shadow-custom-md"
              size="lg"
            >
              Generate Bridge Commands
            </Button>
          </CardContent>
        </Card>

        {/* Generated Commands */}
        <div className="space-y-6">
          {generatedCommands.length === 0 ? (
            <Card className="shadow-custom-lg bg-gradient-card">
              <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                <Info className="w-12 h-12 text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">Ready to Generate</h3>
                <p className="text-muted-foreground">
                  Fill in the network configuration form and click "Generate Bridge Commands" to see the results.
                </p>
              </CardContent>
            </Card>
          ) : (
            generatedCommands.map((command, index) => (
              <Card key={index} className="shadow-custom-lg">
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        <CheckCircle className="w-5 h-5 text-success" />
                        {command.title}
                      </CardTitle>
                      <CardDescription>{command.description}</CardDescription>
                    </div>
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => copyToClipboard(command.commands.join('\n'))}
                      >
                        <Copy className="w-4 h-4" />
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => downloadScript(command)}
                      >
                        <Download className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <Label className="text-sm font-medium">Commands:</Label>
                    <Textarea
                      readOnly
                      value={command.commands.join('\n')}
                      className="mt-2 font-mono text-sm min-h-[200px] bg-muted"
                    />
                  </div>

                  {command.files && command.files.length > 0 && (
                    <div className="space-y-3">
                      <Label className="text-sm font-medium">Configuration Files:</Label>
                      {command.files.map((file, fileIndex) => (
                        <div key={fileIndex} className="space-y-2">
                          <div className="flex items-center justify-between">
                            <Badge variant="outline" className="font-mono text-xs">
                              {file.path}
                            </Badge>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyToClipboard(file.content)}
                            >
                              <Copy className="w-3 h-3" />
                            </Button>
                          </div>
                          <Textarea
                            readOnly
                            value={file.content}
                            className="font-mono text-sm bg-muted"
                            rows={Math.min(file.content.split('\n').length + 1, 10)}
                          />
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="flex items-start gap-2 p-3 bg-warning/10 border border-warning/20 rounded-md">
                    <AlertTriangle className="w-5 h-5 text-warning mt-0.5 flex-shrink-0" />
                    <div className="text-sm">
                      <p className="font-medium text-warning">Important Notes:</p>
                      <ul className="mt-1 space-y-1 text-warning-foreground/80">
                        <li>• Always backup your current network configuration before applying changes</li>
                        <li>• Test these commands in a safe environment first</li>
                        <li>• Ensure you have console access in case network connectivity is lost</li>
                        <li>• Verify your network settings match your infrastructure</li>
                      </ul>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>
      </div>
    </div>
  );
}