# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.170046");
  script_version("2022-03-25T12:45:16+0000");
  script_tag(name:"last_modification", value:"2022-03-28 10:01:15 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-17 20:22:51 +0000 (Thu, 17 Mar 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Icinga Web 2 Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Icinga Web 2.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

port = kb_ssh_transport();

files = ssh_find_bin(prog_name:"icingacli", sock:sock);

foreach file(files) {

  file = chomp(file);

  if(!file)
    continue;

  # Icinga Web 2  2.9.5
  # nb: Two spaces are expected / have been seen like this.
  vers = ssh_get_bin_version(full_prog_name:file, version_argv:"version", ver_pattern:"Icinga Web 2\s+([0-9.]+)", sock:sock);

  if(vers[1]) {

    ssh_close_connection();

    set_kb_item(name:"icinga/icingaweb2/detected", value:TRUE);
    set_kb_item(name:"icinga/icingaweb2/ssh-login/detected", value:TRUE);
    set_kb_item(name:"icinga/icingaweb2/ssh-login/port", value:port);
    set_kb_item(name:"icinga/icingaweb2/ssh-login/" + port + "/installs",
                value:"0#---#" + file + "#---#" + vers[1] + "#---#" + vers[0]);
  }
}

ssh_close_connection();

exit(0);
