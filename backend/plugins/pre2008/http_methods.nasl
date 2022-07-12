###############################################################################
# OpenVAS Vulnerability Test
#
# Test HTTP dangerous methods
#
# Authors:
# Michel Arboi
#
# Copyright:
# Copyright (C) 2000 Michel Arboi
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

# RFCs:
# 1945 Hypertext Transfer Protocol -- HTTP/1.0. T. Berners-Lee, R.
#      Fielding, H. Frystyk. May 1996. (Format: TXT=137582 bytes) (Status:
#      INFORMATIONAL)
# 2068 Hypertext Transfer Protocol -- HTTP/1.1. R. Fielding, J. Gettys,
#      J. Mogul, H. Frystyk, T. Berners-Lee. January 1997. (Format:
#      TXT=378114 bytes) (Obsoleted by RFC2616) (Status: PROPOSED STANDARD)
# 2616 Hypertext Transfer Protocol -- HTTP/1.1. R. Fielding, J. Gettys,
#      J. Mogul, H. Frystyk, L. Masinter, P. Leach, T. Berners-Lee. June
#      1999. (Format: TXT=422317, PS=5529857, PDF=550558 bytes) (Obsoletes
#      RFC2068) (Updated by RFC2817) (Status: DRAFT STANDARD)

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10498");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(12141);
  script_name("Test HTTP dangerous methods");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2000 Michel Arboi");
  script_family("Remote file access");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Use access restrictions to these dangerous HTTP methods
  or disable them completely.");

  script_tag(name:"summary", value:"Misconfigured web servers allows remote clients to perform
  dangerous HTTP methods such as PUT and DELETE.

  This script checks if they are enabled and can be misused to upload or delete files.");

  script_tag(name:"impact", value:"- Enabled PUT method: This might allow an attacker to upload and run arbitrary code on this web server.

  - Enabled DELETE method: This might allow an attacker to delete additional files on this web server.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

report_put_success = 'We could upload the following files via the PUT method at this web server:\n';
report_delete_success = 'We could delete the following files via the DELETE method at this web server:\n';
report_put_no_exploit = 'Although we could not exploit this it seems that the PUT method is enabled (auth protected) at this web server for the following directories:\n';
report_delete_no_exploit = 'Although we could not exploit this it seems that the DELETE method is enabled (auth protected) at this web server for the following directories:\n';

check_text = "A quick brown fox jumps over the lazy dog";

function exists( file, port ) {

  local_var file, port;

  if( http_vuln_check( port:port, url:file, pattern:check_text, check_header:TRUE ) ) {
    return TRUE;
  } else {
    return FALSE;
  }
}

port = get_http_port( default:80 );

put_success = FALSE;
delete_success = FALSE;
put_no_exploit = FALSE;
delete_no_exploit = FALSE;
vuln = FALSE;

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) {
    url = "*"; # TBD: Also check / in addition to * ?
  } else {
    url = dir + "/";
  }

  # Use OPTIONS instead of GET
  req = http_get( item:url, port:port );
  req = str_replace( string:req, find:"GET", replace:"OPTIONS", count:1 );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  # Look for Allow field to check for existing methods later
  allow = egrep( string:res, pattern:"^Allow:" );

  # Rewrite the above set "*"
  if( url == "*" ) url = "/";

  for( i = 1; exists( file:url + "puttest" + i + ".html", port:port ); i++ ) {
    if( i > 3 ) continue; # We could not test this server - really strange.
    # TBD: This was 20 previously but that's way too much from my PoV.
    # I also doubt that this working as expected as the exists() function
    # is also checking for a text pattern...
  }

  file = url + "puttest" + rand() + ".html";

  c = crap( length:77, data:check_text );

  req = http_put( item:file, port:port, data:c );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( exists( port:port, file:file ) ) {
    put_success = TRUE;
    vuln = TRUE;
    report_put_success += '\n' + report_vuln_url( port:port, url:file, url_only:TRUE );
  } else {
    # TBD: Really check only for 401 here?
    if( res =~ "HTTP/1\.. 401" && "PUT" >< allow ) {
      put_no_exploit = TRUE;
      vuln = TRUE;
      report_put_no_exploit += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  }

  if( exists( port:port, file:file ) ) {

    req = http_delete( item:file, port:port );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    # Recheck if file was deleted successfully
    e = exists( port:port, file:file );
  } else {
    e = TRUE;
  }

  if( ! e ) {
    delete_success = TRUE;
    vuln = TRUE;
    report_delete_success  += '\n' + report_vuln_url( port:port, url:file, url_only:TRUE );
  } else {
    # TBD: " is disabled " >!< res && was previously checked here, also really check only for 401 here?
    if( res =~ "HTTP/1\.. 401" && "DELETE" >< allow ) {
      delete_no_exploit = TRUE;
      vuln = TRUE;
      report_delete_no_exploit  += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  }
}

if( vuln ) {

  security_report = "";
  log_report = "";

  if( put_success ) security_report += report_put_success + '\n\n';
  if( delete_success ) security_report += report_delete_success + '\n\n';

  if( put_no_exploit ) log_report += report_put_no_exploit + '\n\n';
  if( delete_no_exploit ) log_report += report_delete_no_exploit + '\n\n';

  if( strlen( security_report ) ) security_message( port:port, data:security_report );
  if( strlen( log_report ) ) log_message( port:port, data:log_report );

  exit( 0 );
}

exit( 99 );