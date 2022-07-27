###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_advantech_webaccess_hmi_designer_detect_win.nasl 13650 2019-02-14 06:48:40Z cfischer $
#
# Advantech WebAccess HMI Designer Version Detection (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813740");
  script_version("2019-04-11T10:25:03+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-04-11 10:25:03 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-08-03 13:25:49 +0530 (Fri, 03 Aug 2018)");
  script_name("Advantech WebAccess HMI Designer Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");

  script_tag(name:"summary", value:"Detects the installed version of Advantech
  WebAccess HMI Designer.

  The script logs in via smb, searches for 'WebAccess HMI Designer' in the
  registry and gets the version from the registry.");

  script_xref(name:"URL", value:"http://www.advantech.com/industrial-automation/webaccess/webaccesshmi");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

if(!registry_key_exists(key:"SOFTWARE\HMI_CONFIGURATION_PROGRAM")) {
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\HMI_CONFIGURATION_PROGRAM")) {
    exit(0);
  }
}

# nb: Only x86-app available
if("x86" >< os_arch)
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

else if("x64" >< os_arch)
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach item(registry_enum_keys(key:key)) {

  hdiName = registry_get_sz(key:key + item, item:"DisplayName");
  if(hdiName && "WebAccess/HMI Designer" >< hdiName) {

    hdiVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    hdiPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!hdiPath)
      hdiPath = "unknown";

    set_kb_item(name:"WebAccess/HMI/Designer/Win/Ver", value:TRUE);
    register_and_report_cpe(app:"Advantech WebAccess HMI Designer",
                            ver:hdiVer,
                            base:"cpe:/a:advantech:webaccess_hmi_designer:",
                            expr:"^([0-9.]+)",
                            insloc:hdiPath,
                            regPort:0,
                            regService:"smb-login");
    exit(0);
  }
}

exit(0);