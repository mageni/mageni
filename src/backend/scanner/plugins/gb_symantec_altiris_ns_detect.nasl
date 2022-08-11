###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_altiris_ns_detect.nasl 11015 2018-08-17 06:31:19Z cfischer $
#
# Symantec Altiris Notification Server Version Detection
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
# ###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800984");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11015 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-02-11 16:37:59 +0100 (Thu, 11 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Symantec Altiris Notification Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the installed version of Symantec Altiris
  Notification Server and sets the result in KB.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Altiris")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  altirisName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Altiris Notification Server" >< altirisName)
  {
    altirisVer1 = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(altirisVer1 != NULL ){
      set_kb_item(name:"Symantec/AltirisNS/Ver", value:altirisVer1);
      log_message(data:"Symantec Altiris Notification Server version " +
                          altirisVer1 + " was detected on the host");

    }
  }

  if("Altiris NS" >< altirisName)
  {
    altirisVer2 = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(altirisVer2 != NULL)
    {
      set_kb_item(name:"Symantec/AltirisNS/SP", value:altirisVer2);
      log_message(data:"Symantec Altiris Notification Server version " +
                          altirisVer2 + " was detected on the host");
    }
  }
}
