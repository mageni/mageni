###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_divx_web_player_detect.nasl 11015 2018-08-17 06:31:19Z cfischer $
#
# DivX Web Player Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900534");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11015 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("DivX Web Player Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the version of DivX Web Player
  and sets the result in KB.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "DivX Web Player Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\DivXNetworks")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  divxName = registry_get_sz(key:key + item, item:"DisplayName");
  if("DivX Web" >< divxName)
  {
    path = registry_get_sz(key:key + item, item:"DisplayIcon");
    if(path == NULL){
      exit(0);
    }
    break;
  }
}

path = path - ",0";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:path);

divVer = GetVer(file:file, share:share);
if(divVer != NULL){
  set_kb_item(name:"DivX/Web/Player/Ver", value:divVer);
  log_message(data:"DivX Web Player version " + divVer +
           " running at location " + path + " was detected on the host");

  cpe = build_cpe(value:divVer, exp:"^([0-9.]+)", base:"cpe:/a:divx:divx_web_player:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

}
