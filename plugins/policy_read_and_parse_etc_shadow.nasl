# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.150500");
  script_version("2020-12-16T14:37:19+0000");
  script_tag(name:"last_modification", value:"2020-12-16 14:37:19 +0000 (Wed, 16 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-11-27 15:12:11 +0000 (Fri, 27 Nov 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Read /etc/shadow");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://linux.die.net/man/5/shadow");

  script_tag(name:"summary", value:"shadow is a file which contains the password information for the
system's accounts and optional aging information.

This file must not be readable by regular users if password security is to be maintained.

Each line of this file contains 9 fields

Note: This script saves setting for other scripts and creates no output.");

  exit(0);
}

include( "ssh_func.inc" );
include( "policy_functions.inc" );

if( ! get_kb_item( "login/SSH/success" ) || ! sock = ssh_login_or_reuse_connection() ) {
  set_kb_item( name:"Policy/linux/etc/shadow/ssh/error", value:TRUE );
  exit( 0 );
}

cmd = "cat /etc/shadow";
ret = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE );

if( ret ) {
  set_kb_item( name:"Policy/linux/etc/shadow/content", value:ret );
}

exit( 0 );