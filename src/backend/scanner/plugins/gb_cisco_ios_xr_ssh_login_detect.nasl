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
  script_oid("1.3.6.1.4.1.25623.1.0.105530");
  script_version("2022-09-21T08:38:59+0000");
  script_tag(name:"last_modification", value:"2022-09-21 08:38:59 +0000 (Wed, 21 Sep 2022)");
  script_tag(name:"creation_date", value:"2016-01-26 17:59:41 +0100 (Tue, 26 Jan 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Cisco IOS XR Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_cisco_show_version.nasl");
  script_mandatory_keys("cisco/show_version");

  script_tag(name:"summary", value:"SSH login-based detection of Cisco IOS XR.");

  exit(0);
}

if (!system = get_kb_item("cisco/show_version"))
  exit(0);

# RP/0/RP0/CPU0:ios#show version
# Fri Sep 16 14:34:56.739 UTC
# Cisco IOS XR Software, Version 7.1.1
#
# Build Information:
#  Built By     : <user>
#  Built On     : <date>
#  Built Host   : <host-name>
#  Workspace    : /auto/srcarchive15/prod/7.1.1/xrv9k/ws
#  Version      : 7.1.1
#  Location     : /opt/cisco/XR/packages/
#  Label        : 7.1.1
#
# cisco IOS-XRv 9000 () processor
# System uptime is 47 minutes

if (!egrep(pattern: "^.* IOS[ -]XR Software.*Version [0-9]+\.[0-9.]+", string: system))
  exit(0);

port = get_kb_item("cisco/ssh-login/port");

set_kb_item(name: "cisco/ios_xr/detected", value: TRUE);
set_kb_item(name: "cisco/ios_xr/ssh-login/detected", value: TRUE);
set_kb_item(name: "cisco/ios_xr/ssh-login/port", value: port);
set_kb_item(name: "cisco/ios_xr/ssh-login/" + port + "/concluded", value: chomp(system));

model = "unknown";
version = "unknown";

vers = eregmatch(pattern: ",\s*Version\s+([0-9]+\.[0-9.]+)", string: system);
if (!isnull(vers[1]))
  version = vers[1];

mod = eregmatch(pattern: "cisco\s+([^(]+)\([^)]*\)\s+processor", string: system);
if (!isnull(mod[1]))
  model = chomp(mod[1]);

set_kb_item(name: "cisco/ios_xr/ssh-login/" + port + "/model", value: model);
set_kb_item(name: "cisco/ios_xr/ssh-login/" + port + "/version", value: version);

exit(0);
