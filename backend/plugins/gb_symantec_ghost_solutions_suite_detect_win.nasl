###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_ghost_solutions_suite_detect_win.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Symantec Ghost Solutions Suite (GSS) Version Detection (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808539");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-07-07 18:14:15 +0530 (Thu, 07 Jul 2016)");
  script_name("Symantec Ghost Solutions Suite (GSS) Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of Symantec
  Ghost Solutions Suite (GSS).

  The script logs in via smb, searches for 'Symantec Ghost Console' installation
  path in the registry and reads the version information from 'ngtray.exe' file.");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(isnull(key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  symName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Symantec Ghost Console and Standard Tools" >< symName)
  {
    symPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(symPath)
    {
      symVer = fetch_file_version(sysPath:symPath, file_name:"ngtray.exe");
      if(symVer != NULL)
      {
        set_kb_item(name:"Symantec/Ghost/Solution/Suite/Installed", value:symVer);

        cpe = build_cpe(value:symVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:ghost_solutions_suite:");
        if(isnull(cpe))
          cpe = "cpe:/a:symantec:ghost_solutions_suite";

        register_product(cpe:cpe, location:symPath);
        log_message(data: build_detection_report(app: "Symantec Ghost Solution Suite",
                                                 version: symVer,
                                                 install: symPath,
                                                 cpe: cpe,
                                                 concluded: symVer));
        exit(0);
      }
    }
  }
}
exit(0);
