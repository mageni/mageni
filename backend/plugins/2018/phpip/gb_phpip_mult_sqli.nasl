###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpip_mult_sqli.nasl 14157 2019-03-13 14:44:46Z cfischer $
#
# phpIP Management 'CVE-2008-0538' Multiple SQL Injection Vulnerabilities
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:phpip:phpip_management";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108432");
  script_version("$Revision: 14157 $");
  script_bugtraq_id(27468);
  script_cve_id("CVE-2008-0538");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 15:44:46 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-03-15 11:36:56 +0100 (Thu, 15 Mar 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("phpIP Management 'CVE-2008-0538' Multiple SQL Injection Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_phpip_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpip_management/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27468");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/487122");

  script_tag(name:"summary", value:"phpIP Management is prone to multiple SQL-injection vulnerabilities
  because it fails to sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and check the response of
  the application.");

  script_tag(name:"insight", value:"The application allows unsanitized SQL commands via the (1) password
  parameter to login.php, the (2) id parameter to display.php, and unspecified other vectors");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"These issues affect phpIP Management 4.3.2. Other versions may also be vulnerable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir  = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/login.php?req=validate";
data = "username=vt-test'&password=vt-test&x=0&y=0&action=login";

req = http_post_req( port:port, url:url, data:data, add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
res = http_keepalive_send_recv( port:port, data:req );

if( res && "mysql_num_rows(): supplied argument is not a valid MySQL result resource" >< res ) {

  err = egrep( pattern:"mysql_num_rows", string:res );

  info['"HTTP POST" body'] = data;
  info['URL'] = report_vuln_url( port:port, url:url, url_only:TRUE );

  report  = 'By doing the following request:\n\n';
  report += text_format_table( array:info ) + '\n';
  report += 'it was possible to execute a SQL injection.';
  report += '\n\nResult: ' + err;

  expert_info = 'Request:\n'+ req + 'Response:\n' + res;
  security_message( port:port, data:report, expert_info:expert_info );
  exit( 0 );
}

exit( 99 );