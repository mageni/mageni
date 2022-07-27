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
  script_oid("1.3.6.1.4.1.25623.1.0.108754");
  script_version("2020-04-22T09:21:14+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-04-23 10:03:00 +0000 (Thu, 23 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-22 08:48:02 +0000 (Wed, 22 Apr 2020)");
  script_name("Huawei VRP Detection (SSH-Banner)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/huawei/vrp/detected");

  script_tag(name:"summary", value:"This script performs an SSH banner based detection of Huawei Versatile Routing Platform (VRP) network devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");

port = ssh_get_port( default:22 );
banner = ssh_get_serverbanner( port:port );
if( ! banner || "SSH-2.0-HUAWEI-" >!< banner )
  exit( 0 );

model = "unknown";
version = "unknown";
patch_version = "unknown";

set_kb_item( name:"huawei/vrp/detected", value:TRUE );
set_kb_item( name:"huawei/vrp/ssh-banner/port", value:port );
set_kb_item( name:"huawei/vrp/ssh-banner/" + port + "/concluded", value:banner );
set_kb_item( name:"huawei/vrp/ssh-banner/" + port + "/version", value:version );
set_kb_item( name:"huawei/vrp/ssh-banner/" + port + "/model", value:model );
set_kb_item( name:"huawei/vrp/ssh-banner/" + port + "/patch", value:patch_version );

exit( 0 );
