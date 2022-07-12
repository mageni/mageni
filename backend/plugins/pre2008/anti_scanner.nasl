###############################################################################
# OpenVAS Vulnerability Test
#
# Anti-Scanner Defenses (HTTP)
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11238");
  script_version("2021-01-21T12:43:45+0000");
  script_tag(name:"last_modification", value:"2021-01-22 11:28:48 +0000 (Fri, 22 Jan 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Anti-Scanner Defenses (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Whitelist the IP of the scanner to e.g. not block/reject HTTP requests
  done by scanner for accurate audit results.");

  script_tag(name:"summary", value:"It seems that the remote web server rejects HTTP requests
  from the Scanner. It is probably protected by a reverse proxy, WAF or IDS/IPS.");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("list_array_func.inc");

waf_headers = make_array(
  "^X-CDN: Incapsula", "Incapsula WAF",
  "^Server:.*mod_security", "ModSecurity WAF"
);

clean_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393";

port = http_get_port( default:80 );
vt_strings = get_vt_strings();

url_test_url1 = "/" + rand_str() + ".html";
url_test_req1 = http_get_req( port:port, url:url_test_url1, user_agent:clean_ua, dont_add_xscanner:TRUE );
url_test_res1 = http_send_recv( port:port, data:url_test_req1 );
if( ! url_test_res1 || ! url_test_status_code1 = egrep( pattern:"^HTTP/[0-9]\.[0-9] [0-9]{3,}", string:url_test_res1, icase:FALSE ) )
  exit( 0 );

url_test_status_code1 = eregmatch( pattern:"^HTTP/[0-9]\.[0-9] ([0-9]{3,})", string:url_test_status_code1, icase:FALSE );
url_test_status_code1 = url_test_status_code1[1];

url_test_url2 = "/" + vt_strings["default_rand"] + ".html";
url_test_req2 = http_get_req( port:port, url:url_test_url2, user_agent:clean_ua, dont_add_xscanner:TRUE );
url_test_res2 = http_send_recv( port:port, data:url_test_req2 );
if( url_test_res2 && url_test_status_code2 = egrep( pattern:"^HTTP/[0-9]\.[0-9] [0-9]{3,}", string:url_test_res2, icase:FALSE ) ) {
  url_test_status_code2 = eregmatch( pattern:"^HTTP/[0-9]\.[0-9] ([0-9]{3,})", string:url_test_status_code2, icase:FALSE );
  url_test_status_code2 = url_test_status_code2[1];
} else {
  url_test_status_code2 = "No response (probably blocked)";
}

if( url_test_status_code1 != url_test_status_code2 ) {
  report = 'By requesting different non-existent URLs the remote web server is answering with different HTTP responses:\n\n';
  info['1. Status Code'] = url_test_status_code1;
  info['1. URL']         = http_report_vuln_url( port:port, url:url_test_url1, url_only:TRUE );
  info['2. Status Code'] = url_test_status_code2;
  info['2. URL']         = http_report_vuln_url( port:port, url:url_test_url2, url_only:TRUE );
  report += text_format_table( array:info );
  log_message( port:port, data:report );
  set_kb_item( name:"www/anti-scanner/" + port + "/rand-url", value:TRUE );
  exit( 0 );
}

ua_test_req1 = http_get_req( port:port, url:"/", user_agent:clean_ua, dont_add_xscanner:TRUE );
ua_test_res1 = http_send_recv( port:port, data:ua_test_req1 );
if( ua_test_res1 && ua_test_status_code1 = egrep( pattern:"^HTTP/[0-9]\.[0-9] [0-9]{3,}", string:ua_test_res1, icase:FALSE ) ) {

  ua_test_status_code1 = eregmatch( pattern:"^HTTP/[0-9]\.[0-9] ([0-9]{3,})", string:ua_test_status_code1, icase:FALSE );
  ua_test_status_code1 = ua_test_status_code1[1];

  ua_test_req2 = http_get_req( port:port, url:"/" );
  ua_test_res2 = http_send_recv( port:port, data:ua_test_req2 );
  if( ua_test_res2 && ua_test_status_code2 = egrep( pattern:"^HTTP/[0-9]\.[0-9] [0-9]{3,}", string:ua_test_res2, icase:FALSE ) ) {
    ua_test_status_code2 = eregmatch( pattern:"^HTTP/[0-9]\.[0-9] ([0-9]{3,})", string:ua_test_status_code2, icase:FALSE );
    ua_test_status_code2 = ua_test_status_code2[1];
  } else {
    ua_test_status_code2 = "No response (probably blocked)";
  }

  if( ua_test_status_code1 != ua_test_status_code2 ) {
    report = 'By sending a different User-Agent the remote web server is answering with different HTTP responses:\n\n';
    info['1. Status Code'] = ua_test_status_code1;
    info['1. User-Agent']  = clean_ua;
    info['2. Status Code'] = ua_test_status_code2;
    info['2. User-Agent']  = http_get_user_agent( dont_add_oid:TRUE );
    report += text_format_table( array:info );
    log_message( port:port, data:report );
    set_kb_item( name:"www/anti-scanner/" + port + "/user-agent", value:TRUE );
  }
}

banner = http_get_remote_headers( port:port );
if( ! banner )
  exit( 0 );

report = 'The following WAF header / banner were identified:\n';

foreach waf_header( keys( waf_headers ) ) {

  desc = waf_headers[waf_header];
  if( ! desc ) # basic santiy check, we should always have a description...
    continue;

  found = egrep( string:banner, pattern:waf_header, icase:TRUE );
  found = chomp( found );

  if( found ) {
    waf_found = TRUE;
    report += '\n' + found + '\n - Description:  ' + desc + '\n - Used pattern: ' + waf_header;
  }
}

if( waf_found ) {
  log_message( port:port, data:report );
  set_kb_item( name:"www/anti-scanner/" + port + "/waf-banner", value:TRUE );
}

exit( 0 );
