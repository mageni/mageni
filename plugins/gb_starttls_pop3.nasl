###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_starttls_pop3.nasl 13822 2019-02-21 21:05:10Z cfischer $
#
# SSL/TLS: POP3 'STLS' Command Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.105008");
  script_version("$Revision: 13822 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 22:05:10 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-04-09 16:29:22 +0100 (Wed, 09 Apr 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSL/TLS: POP3 'STLS' Command Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("popserver_detect.nasl");
  script_require_ports("Services/pop3", 110);
  script_mandatory_keys("pop3/banner/available");

  script_tag(name:"summary", value:"Checks if the remote POP3 server supports SSL/TLS with the 'STLS' command.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc2595");

  exit(0);
}

include("pop3_func.inc");

port = get_pop3_port( default:110 );

if( get_port_transport( port ) > ENCAPS_IP )
  exit( 0 );

soc = pop3_open_socket( port:port );
if( ! soc )
  exit( 0 );

send( socket:soc, data:'STLS\r\n' );
while( buf = recv_line( socket:soc, length:2048 ) ) {
  n++;
  if( eregmatch( pattern:"^\+OK", string:buf, icase:FALSE ) )
    STARTTLS = TRUE;

  if( n > 10 ) # nb: Too much data, we shouldn't expect more then a few lines from a POP3 server
    break;
}

if( STARTTLS ) {

  set_kb_item( name:"pop3/starttls/supported", value:TRUE );
  set_kb_item( name:"pop3/" + port + "/starttls", value:TRUE );
  set_kb_item( name:"starttls_typ/" + port, value:"pop3" );

  report = "The remote POP3 server supports SSL/TLS with the 'STLS' command.";

  capalist = get_kb_list( "pop3/fingerprints/" + port + "/nontls_capalist" );
  if( capalist && typeof( capalist ) == "array" ) {
    capalist = sort( capalist );
    capa_report = "";
    foreach capa( capalist ) {
      if( ! capa_report )
        capa_report = capa;
      else
        capa_report += ", " + capa;
    }
    if( capa_report )
      report = string( report, "\n\nThe remote POP3 server is announcing the following CAPABILITIES before sending the 'STLS' command:\n\n", capa_report );
  }

  # nb: socket_negotiate_ssl() would fork on multiple hostnames causing issues with failed connections
  # / socket communitcation so we're directly disable the use of SNI (and the forking) on this port.
  set_kb_item( name:"Host/SNI/" + port + "/force_disable", value:1 );
  soc = socket_negotiate_ssl( socket:soc );
  if( soc ) {

    send( socket:soc, data:'CAPA\r\n' );
    capabanner = recv_line( socket:soc, length:4096 );
    capabanner = chomp( capabanner );

    # nb: Keep in sync with get_pop3_banner of pop3_func.inc
    if( capabanner && ( capabanner == "+OK" || "capability list follows" >< tolower( capabanner ) || "List of capabilities follows" >< tolower( capabanner ) ||
                        "capa list follows" >< tolower( capabanner ) || "list follows" >< capabanner || "Here's what I can do" >< capabanner ) ) {

      while( capabanner = recv_line( socket:soc, length:4096 ) ) {
        o++;
        capabanner = chomp( capabanner );
        if( capabanner && capabanner != "." ) {
          # nb: Don't set "pop3/fingerprints/" + port + "/nontls_capalist" which is already collected by get_pop3_banner() via popserver_detect.nasl.
          set_kb_item( name:"pop3/fingerprints/" + port + "/tls_capalist", value:capabanner );
        }
        if( o > 128 ) # nb: Too much data...
          break;
      }

      # nb: We're getting the list here again to be able to sort it afterwards for easier comparison with the previous list.
      capalist = get_kb_list( "pop3/fingerprints/" + port + "/tls_capalist" );
      if( capalist && typeof( capalist ) == "array" ) {
        capalist = sort( capalist );
        capa_report = "";
        foreach capa( capalist ) {
          if( ! capa_report )
            capa_report = capa;
          else
            capa_report += ", " + capa;
        }
      }
      if( capa_report )
        report = string( report, "\n\nThe remote POP3 server is announcing the following CAPABILITIES after sending the 'STLS' command:\n\n", capa_report );
    }
    pop3_close_socket( socket:soc );
  }

  log_message( port:port, data:report );
} else {
  pop3_close_socket( socket:soc );
  set_kb_item( name:"pop3/starttls/not_supported", value:TRUE );
  set_kb_item( name:"pop3/starttls/not_supported/port", value:port );
}

exit( 0 );