###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_project_detect_win.nasl 12478 2018-11-22 07:59:26Z santu $
#
# Microsoft Project Version Detection (Windows)
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.814337");
  script_version("$Revision: 12478 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-22 08:59:26 +0100 (Thu, 22 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-19 17:15:31 +0530 (Mon, 19 Nov 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Project Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Microsoft Project
  on Windows.

  The script logs in via smb, searches for Microsoft Project and gets the version
  from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
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
    if("Microsoft Project" >< appName)
    {
      proVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(!proVer){
        exit(0);
      }

      proPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!proPath){
        proPath = "Did not find install path from registry.";
      }

      set_kb_item(name:"Microsoft/Project/Win/Ver", value:proVer);
      cpe = build_cpe(value:proVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:project:");
      if(isnull(cpe))
      cpe = "cpe:/a:microsoft:project";

      register_product(cpe: cpe, location: proPath, service:"smb-login", port:0);

      report =  build_detection_report(app: appName,
                                   version: proVer,
                                   install: proPath,
                                       cpe: cpe,
                                 concluded: proVer);
      if(report){
          log_message( port:0, data:report );
      }
    }
  }
}
