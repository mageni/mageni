###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_greenbone_os_detect_ssh.nasl 8953 2018-02-26 11:57:17Z cfischer $
#
# Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection (SSH)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112136");
  script_version("$Revision: 8953 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-26 12:57:17 +0100 (Mon, 26 Feb 2018) $");
  script_tag(name:"creation_date", value:"2017-11-23 10:47:05 +0100 (Thu, 23 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection (SSH)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl", "gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);

  script_tag(name:"summary", value:"This script performs SSH based detection of the Greenbone Security Manager (GSM) / Greenbone OS (GOS).");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

port = get_ssh_port( default:22 );

if( get_kb_item( "greenbone/gos" ) ) {
  uname = get_kb_item( "greenbone/gos/uname" );
  if( uname ) {
    set_kb_item( name:"greenbone/gos/detected", value:TRUE );
    set_kb_item( name:"greenbone/gos/ssh/detected", value:TRUE );
    set_kb_item( name:"greenbone/gos/ssh/port", value:port );

    version = "unknown";
    vers = eregmatch( pattern:'Welcome to the Greenbone OS ([^ ]+) ', string:uname );
    if( ! isnull( vers[1] ) && vers[1] =~ "^([0-9.-]+)$" ) {
      version   = vers[1];
      concluded = vers[0];
    } else {
      # GOS 4.x+ doesn't report the version in its login banner
      banner = egrep( pattern:"^Welcome to the Greenbone OS.*", string:uname );
      if( banner ) {
        sock = ssh_login_or_reuse_connection();
        # Available since GOS 4+
        cmd = "gsmctl info gsm-info.full_version";
        gsm_info = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE, pty:FALSE );
        if( gsm_info && gsm_info =~ "^([0-9.]+)$" ) {
          version = gsm_info;
          concluded += '\nCommand: ' + cmd;
        }
      }
    }

    type  = "unknown";
    _type = eregmatch( pattern:'running on a Greenbone Security Manager ([^ \r\n]+)', string:uname );
    if( _type[1] ) {
      type       = _type[1];
      concluded += _type[0];
    } else {
      # Available since GOS 4+
      sock = ssh_login_or_reuse_connection();
      cmd = "gsmctl info gsm-info.type";
      gsm_info = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE, pty:FALSE );
      if( gsm_info && gsm_info =~ "^([a-zA-Z0-9.]+)$" ) {
        type = toupper( gsm_info ); # nb: This has e.g. "one" in lower case
        concluded += '\nCommand: ' + cmd;
      }
    }

    set_kb_item( name:"greenbone/gsm/ssh/" + port + "/type", value:type );
    set_kb_item( name:"greenbone/gos/ssh/" + port + "/version", value:version );

    if( concluded )
      set_kb_item( name:"greenbone/gos/ssh/" + port + "/concluded", value:concluded );

    exit( 0 );
  }
}

banner = get_ssh_server_banner( port:port );
if( banner && "Greenbone OS" >< banner ) {
  set_kb_item( name:"greenbone/gos/detected", value:TRUE );
  set_kb_item( name:"greenbone/gos/ssh/detected", value:TRUE );
  set_kb_item( name:"greenbone/gos/ssh/port", value:port );

  vers = eregmatch( pattern:"Greenbone OS ([0-9.-]+)", string:banner );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    set_kb_item( name:"greenbone/gos/ssh/" + port + "/version", value:version );
    set_kb_item( name:"greenbone/gos/ssh/" + port + "/concluded", value:vers[0] );
  }
}

exit( 0 );
