# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.96200");
  script_version("2023-01-23T10:11:56+0000");
  script_tag(name:"last_modification", value:"2023-01-23 10:11:56 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"creation_date", value:"2011-07-13 11:48:37 +0200 (Wed, 13 Jul 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Juniper Networks Junos OS Detection (SSH Login)");

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("junos/detected");

  script_tag(name:"summary", value:"SSH login-based detection of Juniper Networks Junos OS.");

  exit(0);
}

include("ssh_func.inc");

if (!soc = ssh_login_or_reuse_connection())
  exit(0);

port = get_kb_item("ssh/login/juniper/junos/port");

if (get_kb_item("junos/cli"))
  sysversion = ssh_cmd(socket: soc, cmd: "show version detail | no-more", nosh: TRUE);
else
  sysversion = ssh_cmd(socket: soc, cmd: "cli show version detail | no-more");

# Some models/versions don't allow to use a pipe in cli. The first page should contain the needed
# info however.
if (!sysversion)
  sysversion = ssh_cmd(socket:soc, cmd:"cli show version detail");

if (!sysversion || "JUNOS" >!< sysversion)
  exit(0);

version = "unknown";
model = "unknown";
build = "unknown";

set_kb_item(name: "juniper/junos/detected", value: TRUE);
set_kb_item(name: "juniper/junos/ssh-login/port", value: port);
set_kb_item(name: "juniper/junos/ssh-login/" + port + "/concluded", value: sysversion);

set_kb_item(name: "junos/show_version", value: sysversion);

# Junos: 22.3R1.11
vers = eregmatch(pattern: 'Junos: ([^\r\n]+)', string: sysversion);
if (isnull(vers[1]) )
  vers = eregmatch(pattern: "KERNEL ([^ ]+) .+on ([0-9]{4}-[0-9]{2}-[0-9]{2})", string: sysversion);

if (!isnull(vers[1]))
  version = vers[1];

b = eregmatch(pattern: "KERNEL ([^ ]+) .+on ([0-9]{4}-[0-9]{2}-[0-9]{2})", string: sysversion);
if (!isnull(b[2]))
  build = b[2];

# Model: vSRX
mod = eregmatch(pattern: 'Model: ([^\r\n]+)', string: sysversion);
if (!isnull(mod[1]))
  model = mod[1];

set_kb_item(name: "juniper/junos/ssh-login/" + port + "/version", value: version);
set_kb_item(name: "juniper/junos/ssh-login/" + port + "/model", value: model);
set_kb_item(name: "juniper/junos/ssh-login/" + port + "/build_date", value: build);

exit(0);
