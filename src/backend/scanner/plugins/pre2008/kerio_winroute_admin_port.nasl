###############################################################################
# OpenVAS Vulnerability Test
# $Id: kerio_winroute_admin_port.nasl 4829 2016-12-21 11:05:16Z cfi $
#
# Kerio Winroute Firewall Admin Service
#
# Authors:
# Javier Munoz Mellid <jm@udc.es>
#
# Copyright:
# Copyright (C) 2005 Javier Munoz Mellid
# Copyright (C) 2005 Secure Computer Group. University of A Coruna
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.18185");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(13458);
  script_cve_id("CVE-2005-1062", "CVE-2005-1063");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Kerio Winroute Firewall Admin Service");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Javier Munoz Mellid");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(44333);

  script_tag(name:"solution", value:"If this service is not needed, disable it or filter incoming traffic
  to this port.");

  script_tag(name:"summary", value:"The administrative interface of a personal firewall is listening
  on the remote port.

  Description :

  The remote host appears to be running Kerio Winroute Firewall
  Admin service. It is recommended to block incoming traffic
  to this port.

  Also, make sure the use of this software matches your corporate
  security policy.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

function kwf_isWeakAdminProtocol( port ) {

  soc = open_sock_tcp(port);

  if( ! soc ) return 0;

  vuln = TRUE;

  for( i = 0; i < 5; i++ ) {

    s = raw_string( 0x01 );
    send( socket:soc, data:s );

    if( ! soc ) vuln = FALSE;

    r = recv( socket:soc, length:16 );

    if( isnull( r ) || ( strlen( r ) != 2 ) || ( ord( r[0] ) != 0x01 ) || ( ord( r[1] ) != 0x00 ) ) {
      vuln = FALSE;
      break;
    }
  }

  close( soc );

  return vuln;
}

port = 44333; # default kwf port
if( ! get_port_state( port ) )
  exit( 0 );

if( kwf_isWeakAdminProtocol( port ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );