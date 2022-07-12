###############################################################################
# OpenVAS Vulnerability Test
# $Id: imap_unencrypted_cleartext_logins.nasl 13463 2019-02-05 09:40:41Z cfischer $
#
# IMAP Unencrypted Cleartext Login
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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
  script_oid("1.3.6.1.4.1.25623.1.0.15856");
  script_version("$Revision: 13463 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 10:40:41 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_name("IMAP Unencrypted Cleartext Login");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("General");
  script_dependencies("imap4_banner.nasl", "gb_starttls_imap.nasl", "logins.nasl");
  script_require_ports("Services/imap", 143);
  # nb: Don't add imap/(login|password) in the mandatory_keys as the VT can test by using the banners as well.
  script_mandatory_keys("imap/banner/available");

  script_xref(name:"URL", value:"http://www.ietf.org/rfc/rfc2222.txt");
  script_xref(name:"URL", value:"http://www.ietf.org/rfc/rfc2595.txt");

  script_tag(name:"solution", value:"Configure the remote server to always enforce encrypted connections via
  SSL/TLS with the 'STARTTLS' command.");

  script_tag(name:"summary", value:"The remote host is running an IMAP daemon that allows cleartext logins over
  unencrypted connections.

  NOTE: Valid credentials needs to given to the settings of 'Login configurations' OID: 1.3.6.1.4.1.25623.1.0.10870.");

  script_tag(name:"impact", value:"An attacker can uncover user names and passwords by sniffing traffic to the IMAP
  daemon if a less secure authentication mechanism (eg, LOGIN command, AUTH=PLAIN, AUTH=LOGIN) is used.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("misc_func.inc");
include("imap_func.inc");

port = get_imap_port( default:143 );

# IMAPS
encaps = get_port_transport( port );
if( encaps > ENCAPS_IP )
  exit( 0 );

banner = get_imap_banner( port:port );
if( ! banner )
  exit( 0 );

if( get_kb_item( "imap/" + port + "/starttls" ) )
  STARTTLS = TRUE;

# nb: Not all IMAP servers are reporting their CAPABILITIES via the initial banner...
pat = "\[CAPABILITY ([^]]+)";
capas = egrep( string:banner, pattern:pat, icase:TRUE );
capas = chomp( capas );
if( capas ) {
  caps = eregmatch( string:capas, pattern:pat, icase:TRUE );
  if( caps[1] ) {
    capalist = split( caps[1], sep:" ", keep:FALSE );
    capalist = sort( capalist );
  }
}

# ... so try the previously collected CAPABILITIES from the CAPA command of get_imap_banner()
if( ! capalist || ! is_array( capalist ) ) {
  capalist = get_kb_list( "imap/fingerprints/" + port + "/nontls_capalist" );
}

done = FALSE;
if( capalist && is_array( capalist ) ) {
  foreach capa( capalist ) {
    if( capa == "IMAP4rev1" )
      continue;
    if( egrep( string:capa, pattern:"^AUTH=(PLAIN|LOGIN)", icase:FALSE ) ) {
      VULN = TRUE;
      report += '\n' + capa;
    }
    if( egrep( string:capa, pattern:"^LOGINDISABLED", icase:FALSE ) ) {
      # nb: there's no problem.
      break;
    }
  }
  done = TRUE;
}

if( VULN ) {
  report = 'The remote IMAP server accepts logins via the following cleartext authentication mechanisms over unencrypted connections:\n' + report;
  if( STARTTLS )
    report += '\n\nThe remote IMAP server supports the \'STARTTLS\' command but isn\'t enforcing the use of it for the cleartext authentication mechanisms.';
  security_message( port:port, data:report );
  exit( 0 );
}

# nb: We have received the capabilities and know that none of the vulnerable are accepted.
if( done )
  exit( 99 );

if( ! done ) {

  # nb: non US ASCII characters in user and password must be represented in UTF-8.
  kb_creds = imap_get_kb_creds();
  user = kb_creds["login"];
  pass = kb_creds["pass"];
  if( ! user || ! pass )
    exit(0);

  soc = imap_open_socket( port );
  if( ! soc )
    exit( 0 );

  # nb: there's no way to distinguish between a bad username / password
  #     combination and disabled unencrypted logins. This makes it
  #     important to configure the scan with valid IMAP username /
  #     password info.

  # - try the PLAIN SASL mechanism.
  ++tag;
  c = string( "a", string( tag ), ' AUTHENTICATE "PLAIN"' );
  send( socket:soc, data:string( c, "\r\n" ) );
  s = recv_line( socket:soc, length:1024 );
  s = chomp( s );

  if( s =~ "^\+" ) {
    c = base64( str:raw_string(0, user, 0, pass ) );
    send( socket:soc, data:string( c, "\r\n" ) );
    n = 0;
    while( s = recv_line(socket:soc, length:1024 ) ) {
      n++;
      s = chomp( s );

      m = eregmatch( pattern:string( "^a", string( tag ), " (OK|BAD|NO)" ), string:s, icase:TRUE );
      if( ! isnull( m ) ) {
        resp = m[1];
        break;
      }
      resp = "";
      if( n > 256 ) # nb: Too much data...
        break;
    }
  }

  # nb: the obsolete LOGIN SASL mechanism is also dangerous. Since the
  #     PLAIN mechanism is required to be supported, though, I won't
  #     bother to check for the LOGIN mechanism.

  # If that didn't work, try LOGIN command.
  if( isnull( resp ) ) {
    ++tag;
    c = string( "a", string( tag ), " LOGIN ", user, " ", pass );

    send( socket:soc, data:string( c, "\r\n" )) ;
    n = 0;
    while( s = recv_line( socket:soc, length:1024 ) ) {
      n++;
      s = chomp( s );

      m = eregmatch( pattern:string( "^a", string( tag ), " (OK|BAD|NO)" ), string:s, icase:TRUE );
      if( ! isnull( m ) ) {
        resp = m[1];
        break;
      }
      resp = "";
      if( n > 256 ) # nb: Too much data...
        break;
    }
  }

  imap_close_socket( socket:soc, id:tag );

  # If successful, unencrypted logins are possible.
  if( resp && resp =~ "OK" ) {
    report = 'The remote IMAP server accepts logins via the following cleartext authentication mechanisms over unencrypted connections:\nAUTHENTICATE "PLAIN"';
    if( STARTTLS )
      report += '\n\nThe remote IMAP server supports the \'STARTTLS\' command but isn\'t enforcing the use of it for the cleartext authentication mechanisms.';
    security_message( port:port, data:report );
    exit( 0 );
  }
  exit( 99 );
}

exit( 0 );