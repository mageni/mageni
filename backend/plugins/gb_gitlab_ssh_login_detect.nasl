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
  script_oid("1.3.6.1.4.1.25623.1.0.170048");
  script_version("2022-03-25T08:46:34+0000");
  script_tag(name:"last_modification", value:"2022-03-25 11:41:51 +0000 (Fri, 25 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-22 20:39:37 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("GitLab Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of GitLab.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if (!sock)
  exit(0);

port = kb_ssh_transport();

paths = ssh_find_file(file_name:"gitlab/version-manifest\.txt$", useregex:TRUE, sock:sock);

foreach binName (paths) {
  binName = chomp(binName);
  if (!binName)
    continue;

  flavor = "Community Edition";
  # e.g.:
  # gitlab-ce 12.3.5
  # gitlab-ce 14.9.0
  # Note: The version-manifest.txt also contains various additional components like e.g.:
  # Component                      Installed Version                          Version GUID                                                              
  # ----------------------------------------------------------------------------------------------------------------------------------------------------
  # acme-client                    2.0.9
  # alertmanager                   v0.23.0                                    git:29fcb0b7fb8af519fa6c08cfd545d401c98d94e1  
  gitlabVer = ssh_get_bin_version(full_prog_name:"cat", version_argv:binName,
                                  ver_pattern:"gitlab-ce\s+([0-9.]{3,})", sock:sock);
  if (isnull(gitlabVer)) {
    # e.g.:
    # gitlab-ee 14.9.1
    gitlabVer = ssh_get_bin_version(full_prog_name:"cat", version_argv:binName,
                                    ver_pattern:"gitlab-ee\s+([0-9.]{3,})", sock:sock);

    if (isnull(gitlabVer))
      continue;
    else
      flavor = "Enterprise Edition";
  }

  if (gitlabVer[1]) {
    set_kb_item(name:"gitlab/detected", value:TRUE);
    set_kb_item(name:"gitlab/ssh-login/detected", value:TRUE);
    set_kb_item(name:"gitlab/ssh-login/port", value:port);
    set_kb_item(name:"gitlab/ssh-login/" + port + "/installs",
                value:"0#---#GitLab " + flavor + "#---#" + binName + "#---#" + gitlabVer[1] +
                "#---#" + chomp(gitlabVer[0]));
  }
}

ssh_close_connection();

exit(0);
