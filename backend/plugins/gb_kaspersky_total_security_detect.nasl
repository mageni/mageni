##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kaspersky_total_security_detect.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Kaspersky Total Security Version Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.806853");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-02-09 15:43:00 +0530 (Tue, 09 Feb 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Kaspersky Total Security Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Kaspersky Total security  on Windows.

  The script logs in via smb, searches for kaspersky in the registry, gets the
  kaspersky total security installation path from registry and fetches version.");

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

TOTALSEC_LIST = make_list( "^(15\..*)", "cpe:/a:kaspersky:total_security_2015:",
                           "^(16\..*)", "cpe:/a:kaspersky:total_security_2016:");
TOTALSEC_MAX = max_index(TOTALSEC_LIST);

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(isnull(key)){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\KasperskyLab")){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  prdtName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Kaspersky Total Security" >< prdtName)
  {
      ktsVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      insloc = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!insloc){
        insloc = "Could not determine install Path";
      }

      if(ktsVer != NULL)
      {
        set_kb_item(name:"Kaspersky/TotalSecurity/Ver", value:ktsVer);

        for (i = 0; i < TOTALSEC_MAX-1; i = i + 2)
        {
          register_and_report_cpe(app:"Kaspersky Total Security", ver:ktsVer, base:TOTALSEC_LIST[i+1],
                                  expr:TOTALSEC_LIST[i], insloc:insloc);
        }

      }
  }
}
