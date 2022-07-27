###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bullguard_antivirus_detect.nasl 12974 2019-01-08 13:06:45Z cfischer $
#
# BullGuard Antivirus Version Detection (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805274");
  script_version("$Revision: 12974 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 14:06:45 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2015-02-23 12:54:02 +0530 (Mon, 23 Feb 2015)");
  script_name("BullGuard Antivirus Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  BullGuard Anti-Virus.

  The script logs in via smb, searches for 'BullGuard Antivirus' in the registry,
  gets installation path from the registry and then reads version information from
  'version.txt' text file.");

  script_tag(name:"qod_type", value:"registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(!registry_key_exists(key:"SOFTWARE\BullGuard Ltd.")){
  exit(0);
}

## Key is same for 32 bit and 64 bit platform for bullguard
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BullGuard";
if(!registry_key_exists(key:key)){
  exit(0);
}

bgName = registry_get_sz(key:key, item:"DisplayName");

if("BullGuard Antivirus" >< bgName)
{
  bgPath = registry_get_sz(key:key, item:"InstallLocation");

  if(bgPath)
  {
    bgfile = bgPath + "\version.txt";
    txtRead = smb_read_file(fullpath:bgfile, offset:0, count:50);

    bgVer = eregmatch(pattern:"^([0-9.]+)", string:txtRead);
    bgVer = bgVer[1];
    if(bgVer)
    {
      set_kb_item(name:"BullGuard/AntiVirus/Ver", value:bgVer);

      cpe = build_cpe(value:bgVer, exp:"^([0-9.]+)", base:"cpe:/a:bullguard:antivirus:");
      if(isnull(cpe))
        cpe = 'cpe:/a:bullguard:antivirus';

      if("64" >< os_arch)
      {
        set_kb_item(name:"BullGuard/AntiVirus64/Ver", value:bgVer);

        cpe = build_cpe(value:bgVer, exp:"^([0-9.]+)", base:"cpe:/a:bullguard:antivirus:x64:");
        if(isnull(cpe))
          cpe = "cpe:/a:bullguard:antivirus:x64";
      }

      register_product(cpe:cpe, location:bgPath);
      log_message(data: build_detection_report(app: bgName,
                                               version: bgVer,
                                               install: bgPath,
                                               cpe: cpe,
                                               concluded: bgVer));
    }
  }
}
