# OpenVAS Vulnerability Test
# $Id: popserver_detect.nasl 13836 2019-02-25 07:35:49Z cfischer $
# Description: POP3 Server type and version
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Updated by Paul Johnston for Westpoint Ltd <paul@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10185");
  script_version("$Revision: 13836 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-25 08:35:49 +0100 (Mon, 25 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("POP3 Server type and version");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("Service detection");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/pop3", 110, 995);

  script_tag(name:"summary", value:"This detects the POP3 Server's type and version by connecting to
  the server and processing the received banner.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("pop3_func.inc");

ports = pop3_get_ports();
foreach port( ports ) {

  banner = get_pop3_banner( port:port );
  if( ! banner )
    continue;

  if( service_is_unknown( port:port ) )
    register_service( port:port, proto:"pop3", message:"A POP3 Server seems to be running on this port." );

  guess = NULL;
  capas = NULL;

  if( get_port_transport( port ) > ENCAPS_IP )
    is_tls = TRUE;
  else
    is_tls = FALSE;

  set_kb_item( name:"pop3/banner/available", value:TRUE );
  set_kb_item( name:"pop3_imap_or_smtp/banner/available", value:TRUE );

  if( "Dovecot ready" >< banner ) {
    set_kb_item( name:"pop3/dovecot/detected", value:TRUE );
    set_kb_item( name:"pop3/" + port + "/dovecot/detected", value:TRUE );
    guess += '\n- Dovecot';
  }

  if( "POP3 on InetServer" >< banner ) {
    set_kb_item( name:"pop3/avtronics/inetserv/detected", value:TRUE );
    set_kb_item( name:"pop3/" + port + "/avtronics/inetserv/detected", value:TRUE );
    guess += '\n- A-V Tronics InetServ';
  }

  if( "Qpopper" >< banner ) {
    set_kb_item( name:"pop3/qpopper/detected", value:TRUE );
    set_kb_item( name:"pop3/" + port + "/qpopper/detected", value:TRUE );
    guess += '\n- QPopper';
  }

  if( "POP3" >< banner && "MDaemon" >< banner ) {
    set_kb_item( name:"pop3/mdaemon/detected", value:TRUE );
    set_kb_item( name:"pop3/" + port + "/mdaemon/detected", value:TRUE );
    guess += '\n- MDaemon';
  }

  if( "Proxy-POP server (Delegate" >< banner ) {
    set_kb_item( name:"pop3/delegate/detected", value:TRUE );
    set_kb_item( name:"pop3/" + port + "/delegate/detected", value:TRUE );
    guess += '\n- Delegate';
  }

  report = 'Remote POP3 server banner:\n\n' + banner;
  if( strlen( guess ) > 0 )
    report += '\n\nThis is probably:\n' + guess;

  if( is_tls )
    capalist = get_kb_list( "pop3/fingerprints/" + port + "/tls_capalist" );
  else
    capalist = get_kb_list( "pop3/fingerprints/" + port + "/nontls_capalist" );

  if( capalist && is_array( capalist ) ) {
    # Sort to not report changes on delta reports if just the order is different
    capalist = sort( capalist );
    foreach capa( capalist ) {
      if( ! capas )
        capas = capa;
      else
        capas += ", " + capa;
    }
  }

  if( strlen( capas ) > 0 ) {
    capa_report = '\n\nThe remote POP3 server is announcing the following available CAPABILITIES via an ';
    if( is_tls )
      capa_report += "encrypted";
    else
      capa_report += "unencrypted";
    report += capa_report += ' connection:\n\n' + capas;
  }

  log_message( port:port, data:report );
}

exit( 0 );