###############################################################################
# OpenVAS Vulnerability Test
# $Id: anti_nessus.nasl 13659 2019-02-14 08:34:21Z cfischer $
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
  script_version("$Revision: 13659 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Anti-Scanner Defenses (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Change your configuration or whitelist the IP of the scanner to e.g.
  not block/reject HTTP requests done by scanner if you want accurate audit results.");

  script_tag(name:"summary", value:"It seems that your web server rejects HTTP requests
  from the Scanner. It is probably protected by a reverse proxy, WAF or IDS/IPS.");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");

clean_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393";

port = get_http_port( default:80 );
vt_strings = get_vt_strings();

url1 = "/" + vt_strings["default_rand"] + ".html";
req = http_get_req( port:port, url:url1, user_agent:clean_ua, dont_add_xscanner:TRUE );
url_test_res1 = http_send_recv( port:port, data:req );

if( ! url_test_res1 || ! egrep( pattern:"^HTTP/[0-9]\.[0-9] [0-9]+ .*", string:url_test_res1, icase:FALSE ) )
  exit( 0 );

url_test_header1 = ereg_replace( pattern:"^HTTP/[0-9]\.[0-9] ([0-9][0-9][0-9]) .*$", string:url_test_res1, replace:"\1" );
if( url_test_res1 == url_test_header1 )
  url_test_header1 = "";

url2 = "/" + rand_str() + ".html";
req = http_get_req( port:port, url:url2, user_agent:clean_ua, dont_add_xscanner:TRUE );
url_test_res2 = http_send_recv( port:port, data:req );

if( ! url_test_res2 || ! egrep( pattern:"^HTTP/[0-9]\.[0-9] [0-9]+ .*", string:url_test_res2, icase:FALSE ) )
  exit( 0 );

url_test_header2 = ereg_replace( pattern:"^HTTP/[0-9]\.[0-9] ([0-9][0-9][0-9]) .*$", string:url_test_res2, replace: "\1" );
if( url_test_res2 == url_test_header2 )
  url_test_header2 = "";

if( url_test_header1 != url_test_header2 ) {
  report = 'By requesting different non-existent URLs the remote web server is answering with different HTTP responses:\n\n';
  info['1. Status Code'] = url_test_header1;
  info['1. URL']         = report_vuln_url( port:port, url:url1, url_only:TRUE );
  info['2. Status Code'] = url_test_header2;
  info['2. URL']         = report_vuln_url( port:port, url:url2, url_only:TRUE );
  report += text_format_table( array:info );
  log_message( port:port, data:report );
  set_kb_item( name:"www/anti-scanner/" + port + "/rand-url", value:TRUE );
  exit( 0 );
}

req = http_get_req( port:port, url:"/" );
ua_test_res1 = http_send_recv( port:port, data:req );

if( ! ua_test_res1 || ! egrep( pattern:"^HTTP/[0-9]\.[0-9] [0-9]+ .*", string:ua_test_res1, icase:FALSE ) )
  exit( 0 );

ua_test_header1 = ereg_replace( pattern:"^HTTP/[0-9]\.[0-9] ([0-9][0-9][0-9]) .*$", string:ua_test_res1, replace:"\1" );
if( ua_test_res1 == ua_test_header1 )
  ua_test_header1 = "";

req = http_get_req( port:port, url:"/", user_agent:clean_ua, dont_add_xscanner:TRUE );
ua_test_res2 = http_send_recv( port:port, data:req );

if( ! ua_test_res2 || ! egrep( pattern:"^HTTP/[0-9]\.[0-9] [0-9]+ .*", string:ua_test_res2, icase:FALSE ) )
  exit( 0 );

ua_test_header2 = ereg_replace( pattern:"^HTTP/[0-9]\.[0-9] ([0-9][0-9][0-9]) .*$", string:ua_test_res2, replace:"\1" );
if( ua_test_res2 == ua_test_header2 )
  ua_test_header2 = "";

if( ua_test_header1 != ua_test_header2 ) {
  report = 'By sending a different User-Agent header the remote web server is answering with different HTTP responses:\n\n';
  info['1. Status Code'] = ua_test_header1;
  info['1. User-Agent']  = http_get_user_agent( dont_add_oid:TRUE );
  info['2. Status Code'] = ua_test_header2;
  info['2. User-Agent']  = clean_ua;
  report += text_format_table( array:info );
  log_message( port:port, data:report );
  set_kb_item( name:"www/anti-scanner/" + port + "/user-agent", value:TRUE );
}

exit( 0 );