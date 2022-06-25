###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_mult_plugins_sql_inj_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# WordPress Multiple Plugins SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902755");
  script_version("$Revision: 11997 $");
  script_bugtraq_id(49382, 49381);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-17 14:31:04 +0530 (Thu, 17 Nov 2011)");
  script_name("WordPress Multiple Plugins SQL Injection Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45801");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69504");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17757/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17755/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/104610/wpyolink-sql.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/104608/wpcrawlratetracker-sql.txt");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to conduct
  SQL injection attacks.");

  script_tag(name:"affected", value:"WordPress Yolink Search version 1.1.4

  WordPress Crawl Rate Tracker Plugin version 2.0.2");

  script_tag(name:"insight", value:"Refer the references, for information about vulnerability.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running WordPress with multiple plugins and is
  prone to SQL injection vulnerabilities");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);
if(dir == "/") dir = "";

pages = make_list("/wp-content/plugins/crawlrate-tracker/sbtracking-chart-data.php?chart_data=1&page_url='",
                  "/wp-content/plugins/yolink-search/includes/bulkcrawl.php?page='");

foreach page(pages){
  url = dir + page;
  if(http_vuln_check(port:port, url:url, pattern:"(<b>Warning</b>:  ?Invalid argument supplied for foreach\(\)|You have an error in your SQL syntax;)")) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);