###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libssh_server_detect.nasl 13576 2019-02-11 12:44:20Z cfischer $
#
# libssh SSH Server Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108472");
  script_version("$Revision: 13576 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 13:44:20 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-10-17 08:43:06 +0200 (Wed, 17 Oct 2018)");
  script_name("libssh SSH Server Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/libssh/detected");

  script_xref(name:"URL", value:"https://www.libssh.org");

  script_tag(name:"summary", value:"The script sends a connection request to a remote SSH server
  and attempts to identify if it is using libssh and its version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");

port = get_ssh_port( default:22 );
banner = get_ssh_server_banner( port:port );

# SSH-2.0-libssh-0.7.0
# SSH-2.0-libssh
# SSH-2.0-libssh-0.2
#
# nb: This seems to be a "development" version as the git
# master has always something like 0.7.90 or 0.8.90.
# SSH-2.0-libssh_0.7.90
if( banner && banner =~ "^SSH-.*libssh" ) {

  version = "unknown";
  vers = eregmatch( pattern:"^SSH-.*libssh[_-]([0-9.]+)", string:banner );
  if( vers[1] )
    version = vers[1];

  set_kb_item( name:"libssh/server/detected", value:TRUE );

  register_and_report_cpe( app:"libssh Server", ver:version, concluded:banner, base:"cpe:/a:libssh:libssh:", expr:"^([0-9.]+)", regPort:port, insloc:port + "/tcp" );
}

exit( 0 );