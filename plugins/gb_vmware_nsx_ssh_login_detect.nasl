# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105422");
  script_version("2022-02-24T09:13:28+0000");
  script_tag(name:"last_modification", value:"2022-02-24 09:13:28 +0000 (Thu, 24 Feb 2022)");
  script_tag(name:"creation_date", value:"2015-10-27 15:23:03 +0100 (Tue, 27 Oct 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Vmware NSX Detection (SSH Login");

  script_tag(name:"summary", value:"SSH login-based detection of VMware NSX.");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("vmware/nsx/show_ver");

  exit(0);
}

include("host_details.inc");

if (!show_version = get_kb_item("vmware/nsx/show_ver"))
  exit(0);

port = get_kb_item("vmware/nsx/ssh/port");

set_kb_item(name: "vmware/nsx/detected", value: TRUE);
set_kb_item(name: "vmware/nsx/ssh-login/port", value: port);

version = "unknown";
build = "unknown";

vers = eregmatch(pattern: "System Version\s*:\s*([0-9.]+)(-([0-9]+))?", string: show_version);
if (!isnull(vers[1])) {
  version = vers[1];
  set_kb_item(name: "vmware/nsx/ssh-login/" + port + "/concluded", value: vers[0]);
}

if (!isnull(vers[3]))
  build = vers[3];

set_kb_item(name: "vmware/nsx/ssh-login/" + port + "/version", value: version);
set_kb_item(name: "vmware/nsx/ssh-login/" + port + "/build", value: build);

exit(0);
