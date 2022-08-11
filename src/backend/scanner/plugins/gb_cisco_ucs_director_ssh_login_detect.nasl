# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105575");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-09-10T09:51:11+0000");
  script_tag(name:"last_modification", value:"2020-09-10 09:51:11 +0000 (Thu, 10 Sep 2020)");
  script_tag(name:"creation_date", value:"2016-03-17 15:52:18 +0100 (Thu, 17 Mar 2016)");

  script_tag(name:"qod_type", value:"package");

  script_name("Cisco UCS Director Detection (SSH)");

  script_tag(name:"summary", value:"SSH based detection of Cisco UCS Director");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco_ucs_director/show_version");

  exit(0);
}

include("host_details.inc");

show_version = get_kb_item( "cisco_ucs_director/show_version" );
if( ! show_version )
  exit( 0 );

version = "unknown";
build = "unknown";

port = get_kb_item("cisco_ucs_director/ssh_login/port");
set_kb_item(name: "cisco/ucs_director/detected", value: TRUE);
set_kb_item(name: "cisco/ucs_director/ssh-login/port", value: port);
set_kb_item(name: "cisco/ucs_director/ssh-login/" + port + "/concluded", value: show_version);

# Cisco UCS Director Platform
# ------------------
# Version      : 6.7.4.0
# Build Number : 67599
# Press return to continue...
vers = eregmatch(pattern: "Version\s*:\s*([0-9.]+)", string: show_version);
if (!isnull(vers[1]))
  version = vers[1];

bld = eregmatch(pattern: "Build Number\s*:\s*([0-9]+)", string: show_version);
if (!isnull(bld[1]))
  build = bld[1];

set_kb_item(name: "cisco/ucs_director/ssh-login/" + port + "/version", value: version);
set_kb_item(name: "cisco/ucs_director/ssh-login/" + port + "/build", value: build);

exit(0);
