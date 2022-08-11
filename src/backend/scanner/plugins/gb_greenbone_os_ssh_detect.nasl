# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112136");
  script_version("2022-08-10T12:54:52+0000");
  script_tag(name:"last_modification", value:"2022-08-10 12:54:52 +0000 (Wed, 10 Aug 2022)");
  script_tag(name:"creation_date", value:"2017-11-23 10:47:05 +0100 (Thu, 23 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection (SSH)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl", "gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);

  script_tag(name:"summary", value:"SSH based detection of the Greenbone Security Manager (GSM) /
  Greenbone OS (GOS).");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );

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

banner = ssh_get_serverbanner( port:port );
if( banner && "Greenbone OS" >< banner ) {
  set_kb_item( name:"greenbone/gos/detected", value:TRUE );
  set_kb_item( name:"greenbone/gos/ssh/detected", value:TRUE );
  set_kb_item( name:"greenbone/gos/ssh/port", value:port );

  vers = eregmatch( pattern:"Greenbone OS ([0-9.-]+)", string:banner );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    set_kb_item( name:"greenbone/gos/ssh/" + port + "/version", value:version );
    set_kb_item( name:"greenbone/gos/ssh/" + port + "/concluded", value:banner );
  }
}

exit( 0 );
