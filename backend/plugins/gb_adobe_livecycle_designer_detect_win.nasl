###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_livecycle_designer_detect_win.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Adobe LiveCycle Designer Version Detection (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-06-10
# Updated to support 32 and 64 bit.
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802959");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-09-11 16:00:34 +0530 (Tue, 11 Sep 2012)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe LiveCycle Designer Version Detection (Windows)");


  script_tag(name:"summary", value:"Detects the installed version of Adobe LiveCycle Designer.

The script logs in via smb, searches for Adobe LiveCycle Designer in the registry
and gets the version from registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!registry_key_exists(key:"SOFTWARE\Adobe\Designer"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Adobe\Designer")){
    exit(0);
  }
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Presently Adobe LiveCycle Designer 64bit application is not available
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  designName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Adobe LiveCycle Designer" >< designName)
  {
    esName = eregmatch(pattern:"ES([0-9.]+)", string:designName);
    designPath = registry_get_sz(key:key + item, item:"InstallLocation");

    if(designPath)
    {
      designVer = fetch_file_version(sysPath:designPath, file_name:"FormDesigner.exe");

      if(designVer)
      {
        set_kb_item(name:"Adobe/LiveCycle/Designer", value:designVer);

        if(esName[0])
        {
          esName[0] = tolower(esName[0]);
          cpe = build_cpe(value:designVer, exp:"^([0-9.]+)",
                          base:"cpe:/a:adobe:livecycle_designer_" + esName[0] + ":");
        }
        else{
          cpe = build_cpe(value:designVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:livecycle_designer:");
        }

        if(isnull(cpe))
          cpe = "cpe:/a:adobe:livecycle_designer";

        register_product(cpe:cpe, location:designPath);

        log_message(data: build_detection_report(app:"Adobe LiveCycle Designer",
                                                 version:designVer, install:designPath,
                                                 cpe:cpe, concluded: designVer));
      }
    }
  }
}
