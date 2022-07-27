###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_osclass_mult_xss_n_sql_inj_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# OSClass Multiple XSS and SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802970");
  script_version("$Revision: 11857 $");
  script_bugtraq_id(51662);
  script_cve_id("CVE-2012-0973", "CVE-2012-0974", "CVE-2012-5162", "CVE-2012-5163");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-09-27 10:53:49 +0530 (Thu, 27 Sep 2012)");
  script_name("OSClass Multiple XSS and SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47697");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23068");
  script_xref(name:"URL", value:"http://osclass.org/blog/2012/01/16/osclass-2-3-5/");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2012-01/0157.html");
  script_xref(name:"URL", value:"http://www.codseq.it/advisories/multiple_vulnerabilities_in_osclass");

  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site and manipulate SQL queries by injecting arbitrary SQL code.");
  script_tag(name:"affected", value:"OSClass version prior to 2.3.5");
  script_tag(name:"insight", value:"- Input passed via the 'sCategory' GET parameter to /index.php is not
    properly sanitised before being used in SQL query.

  - Input passed via the 'sCity', 'sPattern', 'sPriceMax', 'sPriceMin' GET
    parameters to /index.php is not properly sanitised before being returned
    to the user.

  - Input passed via the 'id' GET parameter in edit_category_post and
    enable_category action is not properly sanitised before being used in
    SQL query.

  - Input passed via the 'id' GET parameter in enable_category action to
    index.php is not properly sanitised before being returned to the user.");
  script_tag(name:"solution", value:"Upgrade to OSClass version 2.3.5 or later.");
  script_tag(name:"summary", value:"This host is running OSClass and is prone to multiple cross site scripting
  and SQL injection vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/osclass/files/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/osclass", cgi_dirs(port:port)))
{
  if(dir == "/") dir = "";
  url = string(dir, "/oc-admin/index.php");

  if(http_vuln_check(port:port, url:url, check_header:TRUE,
     pattern:'>OSClass admin panel login<', extra_check:'"OSClass">'))
  {
    url = string(dir, '/index.php?page=search&sCity="><script>alert(document.cookie);</script>');

    if(http_vuln_check(port:port, url:url, check_header:TRUE,
                       pattern:"><script>alert\(document.cookie\);</script>",
                       extra_check:'>OSClass<'))
    {
      report = report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);