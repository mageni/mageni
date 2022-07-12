###################################################################
# OpenVAS Vulnerability Test
# $Id: panda_av_update_detect.nasl 12974 2019-01-08 13:06:45Z cfischer $
#
# Panda Antivirus Update Detect
#
# LSS-NVT-2010-037
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2010 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102048");
  script_version("$Revision: 12974 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 14:06:45 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2010-07-08 10:59:30 +0200 (Thu, 08 Jul 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Panda Antivirus Update Detect");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Service detection");
  script_dependencies("smb_reg_service_pack.nasl", "gb_panda_prdts_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Panda/Products/Installed");

  script_tag(name:"summary", value:"Extracts date of the last update for Panda Antivirus software, from the
  Titanium.ini file and stores it to KB.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

# This script is tested on Panda Antivirus 2005 through 2007
# For other versions of Panda software might not work due to non-existent titanium.ini file

include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!registry_key_exists(key:"SOFTWARE\Panda Software")){
  exit(0);
}

#reading install directories from the registry
key = "SOFTWARE\Panda Software\";
foreach item (registry_enum_keys(key:key))
{
  ##  Check for the Internet Security
  if("Panda Internet Security" >< item)
    paths[0] = registry_get_sz(key:key + item, item:"DIR");

  ##  Check for the Global Protection
  if("Panda Global Protection" >< item)
    paths[1] = registry_get_sz(key:key + item, item:"DIR");

  ##  Check for the Antivirus
  if("Panda Antivirus" >< item)
    paths[2] = registry_get_sz(key:key + item, item:"DIR");
}

for(i = 0; i < 3; i++){

  if(paths[i]){
    last_update = smb_read_file(fullpath:paths[i] + "\Titanium.ini", offset:0, count:1000);
    last_update = egrep(pattern:"^PavSigDate=(.*)$", string:last_update);
    last_update = ereg_replace(pattern:"^PavSigDate=(.*)$", replace:"\1", string:last_update);
    last_update = last_update - string("\r\n"); #removing the endline chars

    if(!last_update) {
      log_message(data:"Could not find last date of signature base update in file Titanium.ini");
      exit(0);
    }

    set_kb_item(name:"Panda/LastUpdate/Available", value:TRUE);

    if(i == 0)
      set_kb_item(name:"Panda/InternetSecurity/LastUpdate", value:last_update);
    if(i == 1)
      set_kb_item(name:"Panda/GlobalProtect/LastUpdate", value:last_update);
    if(i == 2)
      set_kb_item(name:"Panda/AntiVirus/LastUpdate", value:last_update);
  }
}
