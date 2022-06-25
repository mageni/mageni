###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_starttls_imap.nasl 13822 2019-02-21 21:05:10Z cfischer $
#
# SSL/TLS: IMAP 'STARTTLS' Command Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105007");
  script_version("$Revision: 13822 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-21 22:05:10 +0100 (Thu, 21 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-04-09 15:29:22 +0100 (Wed, 09 Apr 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSL/TLS: IMAP 'STARTTLS' Command Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("imap4_banner.nasl");
  script_require_ports("Services/imap", 143);
  script_mandatory_keys("imap/banner/available");

  script_tag(name:"summary", value:"Checks if the remote IMAP server supports SSL/TLS with the 'STARTTLS' command.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc2595");

  exit(0);
}

include("imap_func.inc");

port = get_imap_port( default:143 );

if( get_port_transport( port ) > ENCAPS_IP )
  exit( 0 );

soc = imap_open_socket( port:port );
if( ! soc )
  exit( 0 );

tag++;
send( socket:soc, data:'A0' + tag + ' STARTTLS\r\n' );

while( buf = recv_line( socket:soc, length:2048 ) ) {
  n++;
  if( eregmatch( pattern:'^A0' + tag + ' OK', string:buf ) )
    STARTTLS = TRUE;

  if( n > 10 ) # nb: Too much data, we shouldn't expect more then a few lines from a IMAP server
    break;
}

if( STARTTLS ) {

  set_kb_item( name:"imap/starttls/supported", value:TRUE );
  set_kb_item( name:"imap/" + port + "/starttls", value:TRUE );
  set_kb_item( name:"starttls_typ/" + port, value:"imap" );

  report = "The remote IMAP server supports SSL/TLS with the 'STARTTLS' command.";

  capalist = get_kb_list( "imap/fingerprints/" + port + "/nontls_capalist" );
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
      report = string( report, "\n\nThe remote IMAP server is announcing the following CAPABILITIES before sending the 'STARTTLS' command:\n\n", capa_report );
  }

  # nb: socket_negotiate_ssl() would fork on multiple hostnames causing issues with failed connections
  # / socket communitcation so we're directly disable the use of SNI (and the forking) on this port.
  set_kb_item( name:"Host/SNI/" + port + "/force_disable", value:1 );
  soc = socket_negotiate_ssl( socket:soc );
  tag++;
  if( soc ) {
    send( socket:soc, data:'A0' + tag + ' CAPABILITY\r\n' );
    banner = recv( socket:soc, length:4096 );

    tag++; # nb: To pass a valid ID to imap_close_socket()
    imap_close_socket( socket:soc, id:tag );

    capas = egrep( string:banner, pattern:"\* CAPABILITY.+IMAP4rev1", icase:TRUE );
    capas = chomp( capas );
    if( capas ) {
      capa_report = "";
      capas = split( capas, sep:" ", keep:FALSE );
      # Sort to not report changes on delta reports if just the order is different
      capas = sort( capas );

      foreach capa( capas ) {

        if( capa == "*" || capa == "CAPABILITY" || capa == "IMAP4rev1" )
          continue;

        if( ! capa_report )
          capa_report = capa;
        else
          capa_report += ", " + capa;

        # nb: Don't set "imap/fingerprints/" + port + "/nontls_capalist" which is already collected by get_imap_banner() via imap4_banner.nasl.
        set_kb_item( name:"imap/fingerprints/" + port + "/tls_capalist", value:capa );
      }
      if( capa_report )
        report = string( report, "\n\nThe remote IMAP server is announcing the following CAPABILITIES after sending the 'STARTTLS' command:\n\n", capa_report );
    }
  }

  log_message( port:port, data:report );
} else {
  tag++;
  imap_close_socket( socket:soc, id:tag );
  set_kb_item( name:"imap/starttls/not_supported", value:TRUE );
  set_kb_item( name:"imap/starttls/not_supported/port", value:port );
}

exit( 0 );