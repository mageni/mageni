###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmydirectory_id_param_sql_inj_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# phpMyDirectory 'id' Parameter SQL Injection Vulnerability
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802977");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-5288");
  script_bugtraq_id(51342);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-10-05 16:54:35 +0530 (Fri, 05 Oct 2012)");
  script_name("phpMyDirectory 'id' Parameter SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47471");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72232");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18338/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will let attacker to inject or manipulate SQL queries
  in the back-end database, allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"phpMyDirectory version 1.3.3");

  script_tag(name:"insight", value:"Input passed via the 'id' parameter to page.php is not properly sanitised
  before being used in SQL queries.");

  script_tag(name:"solution", value:"Upgrade to phpMyDirectory version 1.4.1 or later.");

  script_tag(name:"summary", value:"The host is running phpMyDirectory and is prone to SQL injection
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.phpmydirectory.com/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/phpMyDirectory", "/phpmydirectory", "/pmd", cgi_dirs(port:port))) {

  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( ! res ) continue;

  if( res =~ "HTTP/1.. 200" && '>phpMyDirectory.com<' >< res ) {

    url = dir + "/page.php?id='";

    if(http_vuln_check(port:port, url:url,check_header: TRUE, pattern:'You have an error in your SQL syntax;')) {
      report = report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
