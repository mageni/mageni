###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_npm_packages_detect_ssh.nasl 10834 2018-08-08 11:30:25Z cfischer $
#
# npm Packages Detection (SSH-Login)
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108456");
  script_version("$Revision: 10834 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-08 13:30:25 +0200 (Wed, 08 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-08 13:22:34 +0200 (Wed, 08 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("npm Packages Detection (SSH-Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://www.npmjs.com/");

  script_tag(name:"summary", value:"This script performs SSH login based detection of packages
  installated by the npm package manager.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");

function register_npms( buf ) {
  set_kb_item( name:"ssh/login/npms", value:buf );
}

sock = ssh_login_or_reuse_connection();
buf = ssh_cmd( socket:sock, cmd:"COLUMNS=400 npm list" );

# TBD: Maybe check the npm command before collecting the list to make sure that
# we indeed save the correct list into the KB?
if( ! isnull( buf ) && buf != "" && "command not found" >!< buf )
  register_npms( buf:buf );

exit( 0 );