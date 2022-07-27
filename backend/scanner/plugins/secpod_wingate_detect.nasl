###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wingate_detect.nasl 13267 2019-01-24 12:56:48Z cfischer $
#
# Qbik WinGate Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900324");
  script_version("$Revision: 13267 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-01-24 13:56:48 +0100 (Thu, 24 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_name("Qbik WinGate Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version of Qbik WinGate.

  The script logs in via smb, searches for Qbik WinGate in the registry and
  gets the version from registry.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
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
    appName = registry_get_sz(key:key + item, item:"DisplayName");
    if("WinGate" >< appName)
    {
      appLoc = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!appLoc){
        exit(0);
      }

      winGateVer = fetch_file_version(sysPath:appLoc, file_name:"WinGate.exe");
      if(winGateVer)
      {
        set_kb_item(name:"WinGate/Ver", value:winGateVer);

        cpe = build_cpe(value:winGateVer, exp:"^([0-9.]+)", base:"cpe:/a:qbik:wingate:");
        if(isnull(cpe))
          cpe = "cpe:/a:qbik:wingate";

        ## 64 bit apps on 64 bit platform
        if("x64" >< osArch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"WinGate64/Ver", value:winGateVer);

          cpe = build_cpe(value:winGateVer, exp:"^([0-9.]+)", base:"cpe:/a:qbik:wingate:x64:");
          if(isnull(cpe))
            cpe = "cpe:/a:qbik:wingate:x64";

        }
        register_product(cpe:cpe, location:appLoc);
        log_message(data: build_detection_report(app: appName,
                                                 version: winGateVer,
                                                 install: appLoc,
                                                 cpe: cpe,
                                                 concluded: winGateVer));

      }
    }
  }
}
