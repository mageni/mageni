###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_k7_anti_virus_premium_detect_win.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# K7 Anti-Virus Premium Version Detection (Windows)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.813923");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-03 15:24:05 +0530 (Mon, 03 Sep 2018)");
  script_name("K7 Anti-Virus Premium Version Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  K7 Anti-Virus Premium.

  The script logs in via smb, searches for K7 Anti-Virus Premium
  in the registry and gets the version from 'DisplayVersion' string
  from registry.");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\K7 Computing") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\K7 Computing")){
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
  k7antivirName = registry_get_sz(key:key + item, item:"DisplayName");
  if("K7AntiVirus Premium" >< k7antivirName)
  {
    k7antivirVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    k7antivirPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!k7antivirPath) {
      k7antivirPath = "Unable to find the install location from registry";
    }

    if(k7antivirVer)
    {
      set_kb_item(name:"K7/AntiVirusPremium/Win/Installed", value:TRUE);
      set_kb_item(name:"K7/AntiVirusPremium/Win/Ver", value:k7antivirVer);
      register_and_report_cpe( app:"K7 AntiVirusPremium", ver:k7antivirVer, base:"cpe:/a:k7computing:antivirus_premium:", expr:"^([0-9.]+)", insloc:k7antivirPath );
    }
  }
}
exit(0);
