###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sonic_spot_audioactive_player_detect.nasl 10923 2018-08-10 19:24:58Z cfischer $
#
# Sonic Spot Audioactive Player Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800571");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10923 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 21:24:58 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-06-09 08:37:33 +0200 (Tue, 09 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Sonic Spot Audioactive Player Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"This script detects the version of Sonic Spot Audioactive Player
  and sets the version in KB.");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Sonic Spot Audioactive Player Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}
key = "SOFTWARE\Telos Systems\Audioactive Player";
if(!registry_key_exists(key:key))exit(0);

foreach item (registry_enum_keys(key:key))
{
  audioactiveVer = eregmatch(pattern:"[0-9.]+[a-z]?", string:item);
  if(audioactiveVer != NULL)
  {
    set_kb_item(name:"SonicSpot/Audoiactive/Player/Ver", value:audioactiveVer[0]);

    register_and_report_cpe(app:"Sonic Spot Audioactive Player", ver:audioactiveVer[0],
                            base:"cpe:/a:sonicspot:audioactive_player:", expr:"^([0-9.]+([a-z0-9]+)?)");
    exit(0);
  }
}
