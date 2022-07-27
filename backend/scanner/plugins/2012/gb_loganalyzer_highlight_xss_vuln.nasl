##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_loganalyzer_highlight_xss_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Adiscon LogAnalyzer 'highlight' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802645");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-3790");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-06-21 11:11:11 +0530 (Thu, 21 Jun 2012)");
  script_name("Adiscon LogAnalyzer 'highlight' Parameter Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://secpod.org/blog/?p=504");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SecPod_LogAnalyzer_XSS_Vuln.txt");
  script_xref(name:"URL", value:"http://loganalyzer.adiscon.com/downloads/loganalyzer-3-4-4-v3-stable");
  script_xref(name:"URL", value:"http://loganalyzer.adiscon.com/downloads/loganalyzer-v3-5-5-v3-beta");
  script_xref(name:"URL", value:"http://loganalyzer.adiscon.com/security-advisories/loganalyzer-cross-site-scripting-vulnerability-in-highlight-parameter");

  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");
  script_tag(name:"affected", value:"Adiscon LogAnalyzer versions before 3.4.4 and 3.5.x before 3.5.5");
  script_tag(name:"insight", value:"Input passed via the 'highlight' parameter in index.php is not properly
  verified before it is returned to the user. This can be exploited to execute
  arbitrary HTML and script code in a user's browser session in the context of
  a vulnerable site.");
  script_tag(name:"solution", value:"Upgrade to Adiscon LogAnalyzer version 3.4.4 or 3.5.5 or later.");
  script_tag(name:"summary", value:"This host is running Adiscon LogAnalyzer and is prone to cross site
  scripting vulnerability.");

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

    url += '/?search=Search&highlight="<script>alert(document.cookie)</script>';

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