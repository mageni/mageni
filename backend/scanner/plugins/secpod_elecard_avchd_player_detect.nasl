###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_elecard_avchd_player_detect.nasl 11015 2018-08-17 06:31:19Z cfischer $
#
# Elecard AVC HD Player Application Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900628");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11015 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Elecard AVC HD Player Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"The script detects the Elecard AVC HD Player installed on
  host and sets the version in KB.");
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Elecard AVC HD Player Version Detection";

if (!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

avcVer = registry_get_sz(key:"SOFTWARE\Elecard\Packages\Elecard AVC HD Player",
                         item:"Version");
if(avcVer){
   set_kb_item(name:"Elecard/AVC/HD/Ver", value:avcVer);
   log_message(data:"Elecard AVC HD Player version " + avcVer +
                                                  " was detected on the host");

   cpe = build_cpe(value:avcVer, exp:"^([0-9.]+)", base:"cpe:/a:elecard:elecard_avc_hd_player:");
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

}
