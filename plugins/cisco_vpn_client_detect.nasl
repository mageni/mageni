# OpenVAS Vulnerability Test
# $Id: cisco_vpn_client_detect.nasl 14329 2019-03-19 13:57:49Z cfischer $
# Description: Cisco VPN Client Version Detection
#
# Authors:
# Ferdy Riphagen
# Modified by Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2007 Ferdy Riphagen
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80037");
  script_version("$Revision: 14329 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:57:49 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-10-24 20:38:19 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Cisco VPN Client Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Cisco VPN Client.

The script logs in via smb, searches for Cisco VPN Client in the registry
and gets the version from registry.");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2007 Ferdy Riphagen");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Cisco Systems\VPN Client") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\Cisco Systems\VPN Client")){
  exit(0);
}

if("x86" >< osArch){
  vpnKey = "SOFTWARE\Cisco Systems\VPN Client";
}

else if("x64" >< osArch){
 vpnKey = "SOFTWARE\Wow6432Node\Cisco Systems\VPN Client";
}

vpnPath = registry_get_sz(key:vpnKey, item:"InstallPath");
if(!vpnPath){
  exit(0);
}

vpnVer = GetVersionFromFile(file:vpnPath + "\vpngui.exe", verstr:"prod");
if(!vpnVer){
  exit(0);
}

set_kb_item(name:"SMB/CiscoVPNClient/Version", value:vpnVer);

cpe = build_cpe(value:vpnVer, exp:"^([0-9.]+)", base:"cpe:/a:llnl:slurm:");
if(isnull(cpe))
  cpe = "cpe:/a:llnl:slurm";

## 64 bit apps on 64 bit platform
## Even 64 bit installer creates the key in Wow6432Node
## 32 bit app cannot be installed on 64 bit
if("x64" >< osArch && "Wow6432Node" >< vpnKey)
{
  set_kb_item(name:"SMB/CiscoVPNClient64/Version", value:vpnVer);

  cpe = build_cpe(value:vpnVer, exp:"^([0-9.]+)", base:"cpe:/a:llnl:slurm:x64:");
  if(isnull(cpe))
    cpe = "cpe:/a:llnl:slurm:x64";
}

register_product(cpe:cpe, location:vpnPath);
log_message(data: build_detection_report(app: "Cisco Systems VPN Client",
                                         version: vpnVer,
                                         install: vpnPath,
                                         cpe: cpe,
                                         concluded: vpnVer));
