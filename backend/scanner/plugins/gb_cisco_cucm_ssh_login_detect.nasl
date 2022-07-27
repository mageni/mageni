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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105540");
  script_version("2022-03-10T09:57:15+0000");
  script_tag(name:"last_modification", value:"2022-03-10 11:17:35 +0000 (Thu, 10 Mar 2022)");
  script_tag(name:"creation_date", value:"2016-02-12 12:35:56 +0100 (Fri, 12 Feb 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Cisco Unified Communications Manager (CUCM) Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/cisco/cucm/detected");

  script_tag(name:"summary", value:"SSH login-based detection of Cisco Unified Communications
  Manager (CUCM, formerly Call Manager)");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

if (!get_kb_item("ssh/login/cisco/cucm/detected"))
  exit(0);

if (!port = get_kb_item("ssh/login/cisco/cucm/port"))
  exit(0);

sock = ssh_login_or_reuse_connection();
if (!sock)
  exit(0);

show_ver = ssh_cmd(socket: sock, cmd: "show version active", nosh: TRUE, pty: TRUE, timeout: 60,
                   retry: 30, pattern: "Active Master Version:", clear_buffer: TRUE);

if (!show_ver || "Active Master Version:" >!< show_ver)
  exit(0);

version = "unknown";

set_kb_item(name: "cisco/cucm/detected", value: TRUE);
set_kb_item(name: "cisco/cucm/ssh-login/detected", value: TRUE);
set_kb_item(name: "cisco/cucm/ssh-login/port", value: port);

# Active Master Version: 12.5.1.12900-56
vers = eregmatch(pattern: 'Active Master Version: ([^\r\n]+)', string: show_ver);
if (!isnull(vers[1])) {
  version = vers[1];
  set_kb_item(name: "cisco/cucm/ssh-login/" + port + "/concluded", value: vers[0]);
}

set_kb_item(name: "cisco/cucm/ssh-login/" + port + "/version", value: version);

exit( 0);
