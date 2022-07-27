####################################################################################
# OpenVAS Vulnerability Test
# $Id: gb_docuworks_viewer_light_detect_win.nasl 10906 2018-08-10 14:50:26Z cfischer $
#
# DocuWorks Viewer Light Detection (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811732");
  script_version("$Revision: 10906 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:50:26 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-09-08 15:22:17 +0530 (Fri, 08 Sep 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("DocuWorks Viewer Light Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  DocuWorks Viewer Light.

  The script logs in via smb, searches for 'Xerox DocuWorks Viewer Light' string and
  gets the version from 'DisplayVersion' string from registry.");

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

## Application confirmation, Only 32-bit application is available
if(!registry_key_exists(key:"SOFTWARE\FujiXerox\DocuWorks Viewer Light"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\FujiXerox\DocuWorks Viewer Light")){
    exit(0);
  }
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

## Enumerate all keys
foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Xerox DocuWorks Viewer Light" >< appName)
  {
   appVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(appVer)
    {
      insloc = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insloc){
        insloc = "Could not find install location.";
      }
      set_kb_item(name:"DocuWorks/Viewer/Light/Win/Ver", value:appVer);

      cpe = build_cpe(value:appVer, exp:"([0-9.]+)", base:"cpe:/a:fujixerox:docuworks_viewer_light:");
      if(isnull(cpe))
        cpe = "cpe:/a:fujixerox:docuworks_viewer_light";

      register_product(cpe:cpe, location:insloc);

      log_message(data: build_detection_report(app: "DocuWorks Viewer Light",
                                               version: appVer,
                                               install: insloc,
                                               cpe: cpe,
                                               concluded: appVer));
      exit(0);
    }
  }
}
exit(0);
