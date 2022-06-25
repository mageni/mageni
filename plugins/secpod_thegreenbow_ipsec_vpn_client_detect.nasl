###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_thegreenbow_ipsec_vpn_client_detect.nasl 14329 2019-03-19 13:57:49Z cfischer $
#
# TheGreenBow IPSec VPN Client Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900921");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 14329 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:57:49 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"registry");
  script_name("TheGreenBow IPSec VPN Client Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of TheGreenBow IPSec VPN Client on Windows.

The script logs in via smb, searches for TheGreenBow IPSec VPN Client in the
registry, gets the from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(0);
}

if("x86" >< osArch){
  key_list = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< osArch){
 key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                      "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    vpnName = registry_get_sz(key:key + item, item:"DisplayIcon");

    if("TheGreenBow VPN" >< vpnName)
    {
      path = registry_get_sz(key:key, item:"InstallLocation");
      if(!path){
        path = vpnName - "vpnconf.exe";
      }
      vpnVer = fetch_file_version(sysPath:path, file_name:"vpnconf.exe");
      if(!path){
        path = "Could not find the install location from registry";
      }
      if(vpnVer != NULL)
      {
        set_kb_item(name:"TheGreenBow-IPSec-VPN-Client/Ver", value:vpnVer);
        cpe = build_cpe(value:vpnVer, exp:"^([0-9.]+)", base:"cpe:/a:thegreenbow:thegreenbow_vpn_client:");
        if(!cpe)
          cpe = "cpe:/a:thegreenbow:thegreenbow_vpn_client";

        if("x64" >< osArch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"TheGreenBow-IPSec-VPN-Client64/Ver", value:vpnVer);

          cpe = build_cpe(value:vpnVer, exp:"^([0-9.]+)", base:"cpe:/a:thegreenbow:thegreenbow_vpn_client:x64:");
          if(isnull(cpe))
            cpe = 'cpe:/a:thegreenbow:thegreenbow_vpn_client:x64';

        }
        register_product(cpe:cpe, location:path);
        log_message(data: build_detection_report(app: "TheGreenBow VPN",
                                                 version: vpnVer,
                                                 install: path,
                                                 cpe: cpe,
                                                 concluded: vpnVer));
      }
    }
  }
}
