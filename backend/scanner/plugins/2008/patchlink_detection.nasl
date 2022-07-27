# OpenVAS Vulnerability Test
# $Id: patchlink_detection.nasl 8374 2018-01-11 10:55:51Z cfischer $
# Description: Patchlink Detection
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
# Modified by Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav and Tenable Network Security
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote host has a patch management software installed on it.

Description :

This script uses Windows credentials to detect whether the remote host
is running Patchlink and extracts the version number if so. 

Patchlink is a fully Internet-based, automated, cross-platform, security
patch management system.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302476");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8374 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-11 11:55:51 +0100 (Thu, 11 Jan 2018) $");
 script_tag(name:"creation_date", value:"2008-10-24 20:38:19 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"0.0");
 name = "Patchlink Detection";
 script_name(name);

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav and Tenable Network Security");
 family = "Windows";
 script_family(family);
 script_dependencies("secpod_reg_enum.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_xref(name : "URL" , value : "http://www.patchlink.com/");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.80039";
SCRIPT_DESC = "Patchlink Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(get_kb_item("SMB/samba"))exit(0);

key = "SOFTWARE\PatchLink\Agent Installer";

if(!registry_key_exists(key:key)){
 exit(0);
} 

version = registry_get_sz(item:"Version", key:key);

if (version)
{
  info = string("Patchlink version ", version, " is installed on the remote host.");

  log_message(port:0, data:info);

  set_kb_item(name:"SMB/Patchlink/version", value:version);
  
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:version, exp:"^([0-9]+\.[0-9]+)", base:"cpe:/a:lumension_security:patchlink_update:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

}

exit(0);
