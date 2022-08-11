# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.800335");
  script_version("2021-03-04T06:30:47+0000");
  script_tag(name:"last_modification", value:"2021-03-11 11:26:33 +0000 (Thu, 11 Mar 2021)");
  script_tag(name:"creation_date", value:"2009-01-09 13:48:55 +0100 (Fri, 09 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("OpenSSL Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of OpenSSL.");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

soc = ssh_login_or_reuse_connection();
if (!soc)
  exit(0);

port = kb_ssh_transport();

full_path_list = ssh_find_file(file_name: "/openssl", sock: soc, useregex: TRUE, regexpar: "$");
if (!full_path_list) {
  ssh_close_connection();
  exit(0);
}

foreach full_path (full_path_list) {
  full_path = chomp(full_path);
  if (!full_path)
    continue;

  # OpenSSL 1.1.1f  31 Mar 2020
  vers = ssh_get_bin_version(full_prog_name: full_path, sock:soc, version_argv: "version",
                             ver_pattern: "OpenSSL ([0-9.a-z-]+)");
  if (!isnull(vers[1])) {
    set_kb_item(name: "openssl/detected", value: TRUE);
    set_kb_item(name: "openssl_or_gnutls/detected", value: TRUE);
    set_kb_item(name: "openssl/ssh-login/detected", value: TRUE);
    set_kb_item(name: "openssl/ssh-login/" + port + "/installs",
                value: "0#---#" + full_path + "#---#" + vers[1] + "#---#" + vers[0]);
  }
}

exit(0);
