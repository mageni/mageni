####################################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nitro_pro_detect_win.nasl 10908 2018-08-10 15:00:08Z cfischer $
#
# Nitro Pro Detection (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
####################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811271");
  script_version("$Revision: 10908 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:00:08 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-08-04 14:41:18 +0530 (Fri, 04 Aug 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Nitro Pro Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  Nitro Pro.

  The script logs in via smb, searches for 'Nitro Pro' in the registry
  and gets the version from 'DisplayVersion' string from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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
include("version_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

## Application confirmation
if(!registry_key_exists(key:"SOFTWARE\Nitro\Pro")){
  exit(0);
}

## 32-bit app cannot be installed on 64-bit OS
## Key is same for both architectures
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach item (registry_enum_keys(key:key))
{
  nitName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Nitro Pro" >< nitName)
  {
    nitVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    nitPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!nitPath){
      nitPath = "Couldn find the install location from registry";
    }

    if(nitVer)
    {
      set_kb_item(name:"Nitro/Pro/Win/Ver", value:nitVer);

      cpe = build_cpe(value:nitVer, exp:"^([0-9.]+)", base:"cpe:/a:nitro_software:nitro_pro:");
      if(!cpe)
        cpe = "cpe:/a:nitro_software:nitro_pro";

      ## 32-bit app cannot be installed on 64-bit OS
      if("64" >< os_arch)
      {
        set_kb_item(name:"Nitro/Pro64/Win/Ver", value:nitVer);
        cpe = build_cpe(value:nitVer, exp:"^([0-9.]+)", base:"cpe:/a:nitro_software:nitro_pro:x64:");
        if(!cpe)
          cpe = "cpe:/a:nitro_software:nitro_pro:x64";
      }

      register_product(cpe:cpe, location:nitPath);
      log_message(data: build_detection_report(app:"Nitro Pro", version: nitVer,
                                           install: nitPath, cpe:cpe, concluded:nitVer));
      exit(0);
    }
  }
}
