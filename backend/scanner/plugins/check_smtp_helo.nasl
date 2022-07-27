# OpenVAS Vulnerability Test
# $Id: check_smtp_helo.nasl 13438 2019-02-04 13:36:23Z cfischer $
# Description: SMTP server accepts us
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.18528");
  script_version("$Revision: 13438 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-04 14:36:23 +0100 (Mon, 04 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Check if the SMTP server accepts us");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_dependencies("find_service_3digits.nasl", "smtp_settings.nasl");
  script_require_ports("Services/smtp", 25, 465, 587);

  script_tag(name:"summary", value:"This script does not perform any security test.

  It verifies that the scanner is able to connect to the remote SMTP
  server and that it can send a HELO request.");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("misc_func.inc");
include("smtp_func.inc");

# Some broken servers return _two_ code lines for one query!
# Maybe this function should be put in smtp_func.inc?
function smtp_recv( socket, retry ) {

  local_var r, r2, i, l;

  for( i = 0; i < 6; i++ ) {
    r = recv( socket:socket, length:4096 );
    l = strlen(r);
    if( l == 0 && retry-- <= 0 )
      return r2;
    r2 += r;
    if( l >= 2 && substr( r, l - 2 ) == '\r\n' )
      return r2;
  }
  return r2;
}

ports = smtp_get_ports();

heloname = get_3rdparty_domain();
heloname2 = this_host_name();
if( ! heloname2 )
  heloname2 = this_host();

foreach port( ports ) {

  s = open_sock_tcp( port );
  if( ! s ) {
    smtp_set_is_marked_broken( port:port );
    if( port == 25 )
      smtp_set_is_marked_wrapped( port:port );
    continue;
  }

  r = smtp_recv( socket:s, retry:3 );
  if( ! r ) {
    close( s );
    smtp_set_is_marked_broken( port:port );
    if( port == 25 )
      smtp_set_is_marked_wrapped( port:port );
    continue;
  }

  if( r !~ '^[0-9]{3}[ -]' ) {
    close( s );
    report  = "The SMTP server on this port doesn't answer with 3 ASCII digit codes as expected. It might be possible that it ";
    report += "was mis-identified previously. Answer (truncated): " + substr( r, 0, 500 );
    log_message( port:port, data:report );
    smtp_set_is_marked_broken( port:port );
    continue;
  }

  if( r =~ '^4[0-9]{2}[ -]' ) {
    smtp_close( socket:s, check_data:r );
    report  = "The SMTP server on this port answered with a " + substr( r, 0, 2 ) + " code. ";
    report += "This means that it is temporarily unavailable because it is overloaded or any other reason.";
    report += '\n\nThe scan will be incomplete. You should fix your MTA and rerun the scan, or disable this server if you don\'t use it.';
    log_message( port:port, data:report );
    set_kb_item( name:"smtp/" + port + "/temp_denied", value:TRUE );
    continue;
  }

  if( r =~ '^5[0-9]{2}[ -]' ) {
    smtp_close( socket:s, check_data:r );
    report  = "The SMTP server on this port answered with a " + substr( r, 0, 2 ) + " code. ";
    report += "This means that it is permanently unavailable because the scanner IP is not authorized, blacklisted or any other reason.";
    report += '\n\nThe scan will be incomplete. You may try to scan your MTA from an authorized IP or disable this server if you don\'t use it.';
    log_message( port:port, data:report );
    set_kb_item( name:"smtp/" + port + "/denied", value:TRUE );
    continue;
  }

  used_heloname = heloname;
  send( socket:s, data:'HELO ' + heloname + '\r\n' );
  r = smtp_recv( socket:s, retry:3 );
  if( r =~ '^[45][0-9]{2}[ -]') {
    used_heloname = heloname2;
    send( socket:s, data:'HELO '+ heloname2 + '\r\n' );
    r = smtp_recv( socket:s, retry:3 );
    if( strlen( r ) == 0 ) { # Broken connection ?
      close( s );
      sleep( 1 ); # Try to avoid auto-blacklist
      s = open_sock_tcp( port );
      if( s ) {
        send( socket:s, data:'HELO ' + heloname2 + '\r\n' );
        r = smtp_recv( socket:s, retry:3 );
      }
    }
  }

  smtp_close( socket:s, check_data:r );

  if( r !~ '^2[0-9]{2}[ -]' ) {
    if( strlen( r ) >= 3 )
      report = "The SMTP server on this port answered with a " + substr( r, 0, 2 ) + " code to HELO requests.";
    else
      report = "The SMTP server on this port rejects our HELO requests.";

    report += '\n\nThis means that it is unavailable because the scanner IP is not authorized or blacklisted, or that the scanner hostname is not consistent with it\'s IP.';
    report += '\n\nThe scan will be incomplete. You may try to scan your MTA from an authorized IP or fix the scanner hostname and rescan this server.';
    log_message( port:port, data:report );
    set_kb_item( name:"smtp/" + port + "/denied", value:TRUE );
  } else {
    set_kb_item( name:"smtp/" + port + "/accepted_helo_name", value:used_heloname );
  }
}

exit( 0 );