# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108757");
  script_version("2020-04-24T08:55:51+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-04-27 10:07:29 +0000 (Mon, 27 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-24 08:17:45 +0000 (Fri, 24 Apr 2020)");
  script_name("Huawei VRP Detection (Telnet)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/huawei/vrp/detected");

  script_tag(name:"summary", value:"This script performs an Telnet banner based detection of Huawei Versatile Routing Platform (VRP) network devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("dump.inc");

port = telnet_get_port( default:23 );
banner = telnet_get_banner( port:port );
if( ! banner || "Warning: Telnet is not a secure protocol, and it is recommended to use Stelnet." >!< banner )
  exit( 0 );

model = "unknown";
version = "unknown";
patch_version = "unknown";

set_kb_item( name:"huawei/vrp/detected", value:TRUE );
set_kb_item( name:"huawei/vrp/telnet/port", value:port );
set_kb_item( name:"huawei/vrp/telnet/" + port + "/concluded", value:banner );
set_kb_item( name:"huawei/vrp/telnet/" + port + "/version", value:version );
set_kb_item( name:"huawei/vrp/telnet/" + port + "/model", value:model );
set_kb_item( name:"huawei/vrp/telnet/" + port + "/patch", value:patch_version );

exit( 0 );
