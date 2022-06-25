###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_phantom_detect.nasl 11356 2018-09-12 10:46:43Z tpassfeld $
#
# Foxit Phantom Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801754");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11356 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 12:46:43 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Foxit Phantom Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script finds the Foxit Phantom version and saves
  the result in KB.");
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Foxit Phantom Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
       "\Foxit Phantom";
if(!registry_key_exists(key:key)){
  exit(0);
}

name = registry_get_sz(key:key, item:"DisplayName");
if("Foxit Phantom" >< name)
{
  foxitVer = registry_get_sz(key:key, item:"DisplayVersion");
  if(foxitVer == NULL){
    exit(0);
  }
}

set_kb_item(name:"foxit/phantom/ver", value:foxitVer);
set_kb_item(name:"foxit/phantom_or_reader/detected", value:TRUE);
log_message(data:"Foxit Phantom version " + foxitVer + " was detected on the host");

cpe = build_cpe(value:foxitVer, exp:"^([0-9.]+)", base:"cpe:/a:foxitsoftware:reader:");
if(!isnull(cpe))
   register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

