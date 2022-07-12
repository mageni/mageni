###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_http_security_headers_detect.nasl 10899 2018-08-10 13:49:35Z cfischer $
#
# HTTP Security Headers Detection
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112081");
  script_version("$Revision: 10899 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:49:35 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-10-13 13:12:41 +0200 (Fri, 13 Oct 2017)");
  script_name("HTTP Security Headers Detection");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.owasp.org/index.php/OWASP_Secure_Headers_Project");
  script_xref(name:"URL", value:"https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#tab=Headers");
  script_xref(name:"URL", value:"https://securityheaders.io/");

  script_tag(name:"summary", value:"All known security headers are being checked on the host. On completion a report will hand back whether a specific security header
      has been implemented (including its value) or is missing on the target.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

include("misc_func.inc");

port = get_http_port( default:80 );

banner = get_http_banner( port:port );
if( ! banner || banner !~ "^HTTP/[12]\.[01] (20[0146]|30[12378])" ) exit( 0 );

headers_array = make_array();
missing_array = make_array();

known_headers = make_list( "X-Frame-Options", "X-XSS-Protection", "X-Content-Type-Options", "Content-Security-Policy", "X-Permitted-Cross-Domain-Policies", "Referrer-Policy" );

foreach known_header( known_headers ) {
  headergrep = egrep( string:banner, pattern:"^" + known_header + ": ", icase:TRUE );

  if( headergrep ) {
    found_headers = TRUE;
    headers = split( chomp( headergrep ), sep:": ", keep:FALSE);
    headers_array[headers[0]] = headers[1];

    set_kb_item( name:tolower( known_header ) + "/available", value:TRUE );
    set_kb_item( name:tolower( known_header ) + "/available/port", value:port );
    set_kb_item( name:tolower( known_header ) + "/" + port + "/banner", value:headers[1] );

  } else {
    missing_headers = TRUE;
    missing_array[known_header] = ""; # TBD / TODO: Give some suggestions for default / recommended values?

    set_kb_item( name:tolower( known_header ) + "/missing", value:TRUE );
    set_kb_item( name:tolower( known_header ) + "/missing/port", value:port );
  }
}

if( found_headers ) {
  report += text_format_table( array:headers_array, columnheader:make_list( "Header Name", "Header Value" ) );
}

if( missing_headers ) {
  if( found_headers ) report += '\n';
  # TBD / TODO: Give some suggestions for default / recommended values?
  report += text_format_table( array:missing_array, sep:"", columnheader:make_list( "Missing Headers", "" ) );
}

if( strlen( report ) > 0 )
  log_message( port:port, data:report );

exit( 0 );