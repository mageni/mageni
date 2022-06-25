###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Network Analysis Module Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105457");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-06-25T10:23:49+0000");
  script_tag(name:"last_modification", value:"2020-06-30 10:45:10 +0000 (Tue, 30 Jun 2020)");
  script_tag(name:"creation_date", value:"2015-11-18 12:57:00 +0100 (Wed, 18 Nov 2015)");

  script_name("Cisco Network Analysis Module Detection (SSH-Login)");

  script_tag(name:"summary", value:"This script performs SSH based detection of Cisco Network Analysis Module.");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco_nam/show_ver");

  exit(0);
}

include("host_details.inc");

show_ver = get_kb_item("cisco_nam/show_ver");

# NAM application image version: 5.0(1T.45) INTERIM SOFTWARE
# Helper Version: 1.1(0.19)
# Gold Helper Version: 1.1(0.19)
# PID: WS-SVC-NAM-3-K9Memory size: 23 GBDisk 0 size: 8 GBDisk 1 size: 600 GB
if( ! show_ver || "NAM application image version" >!< show_ver )
  exit( 0 );

version = "unknown";
patch = "unknown";

port = get_kb_item("cisco_nam/ssh-login/port");
set_kb_item( name:"cisco/nam/detected", value:TRUE );
set_kb_item( name:"cisco/nam/ssh-login/port", value:port );
set_kb_item( name:"cisco/nam/ssh-login/" + port + "/concluded", value:show_ver );

vers = eregmatch( pattern:'NAM application image version: ([^\r\n]+)', string:show_ver );

if( ! isnull( vers[1] )) {
  if( "-patch" >< vers[1] ) {
    v = split( vers[1], sep:"-", keep:FALSE );
    if( ! isnull( v[0] ) )
      version = str_replace( string:v[0], find:"(", replace:".");

    if( ! isnull( v[1] ) ) {
      p = eregmatch( pattern:'patch([0-9]+)', string:v[1] );
      if( ! isnull( p[1] ) )
        patch =  p[1];
    }
  }
  else {
    vers = split( vers[1], sep:" ", keep:FALSE );
    version = ereg_replace( string:vers[0], pattern:"\(([0-9A-Za-z.]+)\)", replace:".\1");
  }
}

set_kb_item( name:"cisco/nam/ssh-login/" + port + "/version", value:version );
set_kb_item( name:"cisco/nam/ssh-login/" + port + "/patch", value:patch );

pid = eregmatch( pattern:'PID: ([^\r\n]+)', string:show_ver );

if( ! isnull( pid[1] ) ) {
  if( "ESX" >< pid[1] )
    set_kb_item( name:"cisco/nam/vnam", value:TRUE);

  set_kb_item( name:"cisco/nam/pid", value:pid[1] );
}

exit( 0 );
