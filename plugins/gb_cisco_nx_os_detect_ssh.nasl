###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_nx_os_detect_ssh.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco NX-OS Detection (SSH)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103817");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-21 11:24:09 +0200 (Mon, 21 Oct 2013)");
  script_name("Cisco NX-OS Detection (SSH)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_show_version.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("cisco/show_version");
  script_tag(name:"summary", value:"This script performs SSH based detection of Cisco NX-OS.");
  script_tag(name:"qod_type", value:"package");


  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

show_ver = get_kb_item("cisco/show_version");

if( "Cisco Nexus Operating System (NX-OS) Software" >!< show_ver ) exit( 0 );

set_kb_item( name:"cisco/nx_os/detected", value:TRUE );

vers =  "unknown";
model  = "unknown";
device = "unknown";
source = "ssh";

version = eregmatch( pattern:"system:\s+version\s+([0-9a-zA-Z\.\(\)]+)[^\s\r\n]*", string: show_ver );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  set_kb_item( name:"cisco/nx_os/" + source + "/version", value: vers );
}

if( "MDS" >< show_ver )
  device = "MDS";
else
  device = "Nexus";

lines = split( show_ver, keep:FALSE );

foreach line (lines) {
  if( "Chassis" >!< line ) continue;
  mod = eregmatch( pattern:"cisco (Unknown|Nexus|MDS)\s(.*)\sChassis", string: line, icase:TRUE );
  break;
}

if( ! isnull( mod[2] ) )
  model = mod[2];

set_kb_item(name:"cisco/nx_os/" + source + "/device", value:device);
set_kb_item(name:"cisco/nx_os/" + source + "/model", value:model);

exit(0);
