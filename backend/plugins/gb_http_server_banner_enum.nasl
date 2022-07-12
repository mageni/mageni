# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108708");
  script_version("2020-02-04T13:13:40+0000");
  script_tag(name:"last_modification", value:"2020-02-04 13:13:40 +0000 (Tue, 04 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-04 08:19:51 +0000 (Tue, 04 Feb 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("HTTP Server Banner Enumeration");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "find_service2.nasl", "apache_SSL_complain.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script tries to detect / enumerate different HTTP server banner (e.g. from a
  frontend, backend or proxy server) by sending various different HTTP requests (valid and invalid ones).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");

found_headers = make_array();
enum_headers  = '^((DAAP-)?Server|User-Agent|X-Powered-By)\\s*:[^\r\n]+';

function create_http_enum_reqs( port, host ) {

  local_var port, host;
  local_var enum_reqs, files, vt_strings, http_verbs, file, http_verb, url;

  enum_reqs = make_array();

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#create_http_enum_reqs" );
    return enum_reqs;
  }

  if( ! host ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#host#-#create_http_enum_reqs" );
    return enum_reqs;
  }

  files = make_list( "index.php", "index.asp", "index.aspx", "index.html",
                     "index.htm", "index.pl", "index.py", "index.cgi",
                     "index.cfm", "index.jsp", "index.action", "index.do" );

  vt_strings = get_vt_strings();

  http_verbs = make_list( "GET", "HEAD", "PUT", "POST", "custom" );

  foreach file( files ) {

    url = "/" + file;

    foreach http_verb( http_verbs ) {

      # nb: Syntax is:
      # array key   -> Plain request
      # array value -> Short description
      if( http_verb == "custom" ) {
        http_verb = vt_strings["uppercase"];
        enum_reqs[http_verb + ' ' + url + ' HTTP/1.1\r\nHost: ' + host + '\r\nConnection: close\r\n\r\n'] = "Invalid HTTP 1.1 " + http_verb + " request (non-existent HTTP verb) to '" + url + "'";
        enum_reqs[http_verb + ' ' + url + ' HTTP/1.0\r\n\r\n'] = "Invalid HTTP 1.0 " + http_verb + " request (non-existent HTTP verb) to '" + url + "'";
        enum_reqs[http_verb + ' ' + url + ' HTTP/0.9\r\n\r\n'] = "Invalid HTTP 0.9 " + http_verb + " request (non-existent HTTP verb) to '" + url + "'";
      } else {
        enum_reqs[http_verb + ' ' + url + ' HTTP/1.1\r\nHost: ' + host + '\r\nConnection: close\r\n\r\n'] = "Valid HTTP 1.1 " + http_verb + " request to '" + url + "'";
        enum_reqs[http_verb + ' ' + url + ' HTTP/1.0\r\n\r\n'] = "Valid HTTP 1.0 " + http_verb + " request to '" + url + "'";
        enum_reqs[http_verb + ' ' + url + ' HTTP/0.9\r\n\r\n'] = "Valid HTTP 0.9 " + http_verb + " request to '" + url + "'";
        enum_reqs[http_verb + ' ' + url + ' HTTP/1.1\r\n\r\n'] = "Invalid HTTP 1.1 " + http_verb + " request (Mandatory Host and Connection header missing) to '" + url + "'";
        enum_reqs[http_verb + ' ' + url + ' HTTP/00.5\r\n\r\n'] = "Invalid HTTP 00.5 " + http_verb + " request (non-existent HTTP version) to '" + url + "'";
      }
    }

    # nb: Keep at the bottom because the target might block our requests / probes based on our
    # User-Agent header and we want to catch as many info as possible before getting blocked.
    enum_reqs[http_get_req( port:port, url:url )] = "Valid HTTP 1.1 GET request (with extended headers) to '" + url + "'";
    enum_reqs[http_post_req( port:port, url:url, data:"" )] = "Valid HTTP 1.1 POST request (with extended headers) to '" + url + "'";
  }

  return enum_reqs;
}

port = get_http_port( default:80 );

# nb: Always keep http_host_name() before http_open_socket() as the first
# could fork with multiple vhosts and the child's would share the same
# socket causing race conditions and similar.
host = http_host_name( port:port );

req_array = create_http_enum_reqs( port:port, host:host );
found_numbers = 0;
foreach req( keys( req_array ) ) {

  soc = http_open_socket( port );
  if( ! soc )
    continue;

  send( socket:soc, data:req );
  headers = http_recv_headers2( socket:soc );
  http_close_socket( soc );
  if( ! headers || headers !~ "^HTTP/(0\.9|1\.[01]|2) [0-9]{3}" )
    continue;

  if( found_header = egrep( string:headers, pattern:enum_headers, icase:TRUE ) ) {
    splitted_headers = split( found_header, sep:'\r\n', keep:FALSE );
    foreach splitted_header( splitted_headers ) {
      splitted_header = chomp( splitted_header );
      splitted_header = eregmatch( string:splitted_header, pattern:enum_headers, icase:TRUE );
      if( splitted_header[0] && ! array_key_exist( key:splitted_header[0], array:found_headers, part_match:FALSE ) ) {
        found_numbers++;
        found_headers[splitted_header[0]] = req_array[req];
      }
    }
  }
}

if( found_numbers > 0 ) {

  report = 'It was possible to enumerate the following HTTP server banner(s):\n\n';

  # nb: If something went wrong (e.g. a server banner including a dynamic text or similar)
  # we're limiting the reported headers to only two (at least for now).
  if( found_numbers > 10 )
    maxentries = 2;

  report += text_format_table( array:found_headers, columnheader:make_list( "Server banner", "Enumeration technique" ), maxentries:maxentries, sep:" | " );
  log_message( port:port, data:report );
}

exit( 0 );
