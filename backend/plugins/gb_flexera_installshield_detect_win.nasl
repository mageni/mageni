###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flexera_installshield_detect_win.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Flexera InstallShield Version Detection (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809005");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-08-19 19:16:31 +0530 (Fri, 19 Aug 2016)");
  script_name("Flexera InstallShield Version Detection (Windows)");
  script_tag(name:"summary", value:"Detects the installed version of
  Flexera InstallShield.

  The script logs in via smb, searches for InstallShield in the registry
  and gets the version from 'DisplayVersion' string from registry.");

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

TOTALSEC_LIST = make_list( "^(22\..*)", "cpe:/a:flexerasoftware:installshield:2015:",
                           "^(21\..*)", "cpe:/a:flexerasoftware:installshield:2014:",
                           "^(20\..*)", "cpe:/a:flexerasoftware:installshield:2013:");
TOTALSEC_MAX = max_index(TOTALSEC_LIST);

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\InstallShield") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\InstallShield")){
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
  inshieldName = registry_get_sz(key:key + item, item:"DisplayName");

  if(inshieldName =~ "InstallShield( 2015| 2014| 2013)?$")
  {
    inshieldVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    inshieldPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!inshieldPath){
      inshieldPath = "Unable to find the install location from registry";
    }

    if(inshieldVer != NULL)
    {
      set_kb_item(name:"Flexera/InstallShield/Win/Ver", value:inshieldVer);

      ## http://www.flexerasoftware.com/producer/support/additional-support/end-of-life/installshield.html
      for (i = 0; i < TOTALSEC_MAX-1; i = i + 2)
      {
        register_and_report_cpe(app:"Flexera InstallShield", ver:inshieldVer, base:TOTALSEC_LIST[i+1],
                                expr:TOTALSEC_LIST[i], insloc:inshieldPath);
      }
    }
  }
}
