# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.146147");
  script_version("2021-06-18T07:48:29+0000");
  script_tag(name:"last_modification", value:"2021-06-18 10:19:50 +0000 (Fri, 18 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-18 03:03:16 +0000 (Fri, 18 Jun 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("OpenLDAP Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of OpenLDAP.");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

soc = ssh_login_or_reuse_connection();
if (!soc)
  exit(0);

port = kb_ssh_transport();

paths = ssh_find_file(file_name: "/slapd$", sock: soc, useregex: TRUE);

foreach file (paths) {
  version = "unknown";

  file = chomp(file);
  if (!file)
    continue;

  # @(#) $OpenLDAP: slapd 2.4.46 $
  # @(#) $OpenLDAP: slapd 2.4.44 (Apr 28 2021 13:32:00) $
  # @(#) $OpenLDAP: slapd  (Ubuntu) (Apr  8 2021 04:22:01) $
  # @(#) $OpenLDAP: slapd  (Feb 14 2021 18:32:34) $
  # @(#) $OpenLDAP: slapd 2.4.49 (Jun  2 2021 09:00:31) $
  res = ssh_cmd(socket: soc, cmd: file + " -V");
  if ("OpenLDAP: slapd " >< res) {
    vers = eregmatch(pattern: "OpenLDAP: slapd ([0-9.]+)", string: res);
    if (!isnull(vers[1]))
      version = vers[1];

    set_kb_item(name: "openldap/detected", value: TRUE);
    set_kb_item(name: "openldap/ssh-login/detected", value: TRUE);
    set_kb_item(name: "openldap/ssh-login/" + port + "/installs", value: "0#---#" + file + "#---#" + version + "#---#" + res);
  }
}

exit(0);
