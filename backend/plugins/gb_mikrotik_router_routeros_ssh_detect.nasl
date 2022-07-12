# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108548");
  script_version("$Revision: 13593 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 08:36:53 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-12 08:27:22 +0100 (Tue, 12 Feb 2019)");
  script_name("MikroTik RouterOS Detection (SSH)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/mikrotik/routeros/detected");

  script_tag(name:"summary", value:"Detection of MikroTik RouterOS via SSH.

  The script sends a connection request to the server and attempts to
  detect the presence of MikroTik Router.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

port = get_ssh_port( default:22 );
banner = get_ssh_server_banner( port:port );
if( ! banner || "SSH-2.0-ROSSSH" >!< banner )
  exit( 0 );

version = "unknown";
install = port + "/tcp";
set_kb_item( name:"mikrotik/detected", value:TRUE );
set_kb_item( name:"mikrotik/ssh/detected", value:TRUE );

set_kb_item( name:"mikrotik/ssh/" + port + "/concluded", value:banner );
set_kb_item( name:"mikrotik/ssh/port", value:port );
set_kb_item( name:"mikrotik/ssh/" + port + "/version", value:version );

exit( 0 );