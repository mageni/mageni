# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103817");
  script_version("2022-12-12T04:49:09+0000");
  script_tag(name:"last_modification", value:"2022-12-12 04:49:09 +0000 (Mon, 12 Dec 2022)");
  script_tag(name:"creation_date", value:"2013-10-21 11:24:09 +0200 (Mon, 21 Oct 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Cisco NX-OS Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_cisco_show_version.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("cisco/show_version");

  script_tag(name:"summary", value:"SSH login-based detection of Cisco NX-OS.");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

if (!show_ver = get_kb_item("cisco/show_version"))
  exit(0);

# Cisco Nexus Operating System (NX-OS) Software
# ...
# Nexus 9000v is a demo version of the Nexus Operating System
#
# Software
#   BIOS: version
#   NXOS: version 10.3(1) Feature Release]
#   BIOS compile time:
#   NXOS image file is: bootflash:///nxos64-cs-lite.10.3.1.F.bin
#   NXOS compile time:  8/18/2022 15:00:00 08/19/2022 05:52:41]
#
# Hardware
#   cisco Nexus9000 C9300v Chassis
#    with 10201784 kB of memory.
# --More--  Processor Board ID 9UA6WOQ6LF5
# --More--  Device name: switch
# --More--  bootflash:    4287040 kB
# --More--
# --More--Kernel uptime is 0 day(s), 0 hour(s), 47 minute(s), 12 second(s)
# --More--
# --More--Last reset
# --More--  Reason: Unknown
# --More--  System version:
# --More--  Service:
# --More--
# --More--plugin
# --More--  Core Plugin, Ethernet Plugin
# --More--
if ("Cisco Nexus Operating System (NX-OS) Software" >!< show_ver)
  exit(0);

# Strip away any unneeded content before 'show version'
start = stridx(show_ver, "show version");
if (start > 0)
  show_ver = substr(show_ver, start);

port = get_kb_item("cisco/ssh-login/port");

set_kb_item(name: "cisco/nx_os/detected", value: TRUE);
set_kb_item(name: "cisco/nx_os/ssh-login/detected", value: TRUE);
set_kb_item(name: "cisco/nx_os/ssh-login/port", value: port);
set_kb_item(name: "cisco/nx_os/ssh-login/" + port + "/concluded", value: chomp(show_ver));

version =  "unknown";
model   = "unknown";
device  = "unknown";

vers = eregmatch(pattern: "system:\s+version\s+([0-9a-zA-Z\.\(\)]+)[^\s\r\n]*", string: show_ver);
if (isnull(vers[1]))
  vers = eregmatch(pattern: "NXOS\s*:\s*version ([0-9a-zA-Z.\(\)]+)", string: show_ver);

if (!isnull(vers[1]))
  version = vers[1];

if ("MDS" >< show_ver)
  device = "MDS";
else
  device = "Nexus";

lines = split(show_ver, keep: FALSE);

foreach line (lines) {
  if ("Chassis" >!< line)
    continue;

  mod = eregmatch(pattern: "cisco (Unknown|Nexus[0-9]+?|MDS)\s(.*)\s+Chassis", string: line, icase: TRUE);
  break;
}

if (!isnull(mod[2]))
  model = mod[2];

set_kb_item(name: "cisco/nx_os/ssh-login/" + port + "/version", value: version);
set_kb_item(name: "cisco/nx_os/ssh-login/" + port + "/device", value: device);
set_kb_item(name: "cisco/nx_os/ssh-login/" + port + "/model", value: model);

exit(0);
