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
  script_oid("1.3.6.1.4.1.25623.1.0.150576");
  script_version("2021-01-27T15:10:53+0000");
  script_tag(name:"last_modification", value:"2021-02-03 11:17:41 +0000 (Wed, 03 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-01-27 14:44:55 +0000 (Wed, 27 Jan 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Get content of configuration files");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Get content of relevant Linux config files like /etc/shadow,
/etc/passwd and other");

  exit(0);
}

include( "ssh_func.inc" );
include( "policy_functions.inc" );

if( ! get_kb_item( "login/SSH/success" ) || ! sock = ssh_login_or_reuse_connection() ) {
  set_kb_item( name:"policy/linux/file_content/error", value:TRUE );
  exit( 0 );
}

files = make_list("/etc/passwd",
  "/etc/shadow",
  "/etc/group");

foreach file (files){
  policy_linux_file_content(socket:sock, file:file);
}

exit( 0 );