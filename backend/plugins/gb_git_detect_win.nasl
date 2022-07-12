###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_git_detect_win.nasl 10901 2018-08-10 14:09:57Z cfischer $
#
# Git Version Detection (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809817");
  script_version("$Revision: 10901 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:09:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-11-23 16:58:28 +0530 (Wed, 23 Nov 2016)");
  script_name("Git Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  Git.

  The script logs in via smb, searches for 'Git Version' in the registry,
  gets version and installation path information from the registry.");

  script_tag(name:"qod_type", value:"registry");

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

##Key based on architecture
if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    gitName = registry_get_sz(key:key + item, item:"DisplayName");

    if("Git version" >< gitName)
    {
      gitVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      gitPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!gitPath)
      {
        gitPath = "Unable to find the install location from registry";
      }
      set_kb_item(name:"Git/Win/Ver", value:gitVer);

      cpe = build_cpe(value:gitVer, exp:"^([0-9.]+)", base:"cpe:/a:git_for_windows_project:git_for_windows:");
      if(isnull(cpe))
        cpe = "cpe:/a:git_for_windows_project:git_for_windows";

      if("64" >< os_arch)
      {
        set_kb_item(name:"Git/x64/Win/Ver", value:gitVer);
        cpe = build_cpe(value:gitVer, exp:"^([0-9.]+)", base:"cpe:/a:git_for_windows_project:git_for_windows:x64:");

        if(isnull(cpe))
        cpe = "cpe:/a:git_for_windows_project:git_for_windows:x64";
      }
      register_product(cpe:cpe, location:gitPath);
      log_message(data: build_detection_report(app: gitName,
                                               version: gitVer,
                                               install: gitPath,
                                               cpe: cpe,
                                               concluded: gitVer));
    }
  }
}
