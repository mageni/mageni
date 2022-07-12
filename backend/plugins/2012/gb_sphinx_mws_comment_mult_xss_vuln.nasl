###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sphinx_mws_comment_mult_xss_vuln.nasl 11430 2018-09-17 10:16:03Z cfischer $
#
# Sphinx Mobile Web Server 'comment' Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802390");
  script_version("$Revision: 11430 $");
  script_cve_id("CVE-2012-1005");
  script_bugtraq_id(51820);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 12:16:03 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-02-02 14:49:35 +0530 (Thu, 02 Feb 2012)");
  script_name("Sphinx Mobile Web Server 'comment' Multiple Cross-Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://secpod.org/blog/?p=453");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47876");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72913");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18451/");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SecPod_SPHINX_SOFT_Mobile_Web_Server_Mul_Persistence_XSS_Vulns.txt");

  script_category(ACT_DESTRUCTIVE_ATTACK); # Stored XSS
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("MobileWebServer/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site.");
  script_tag(name:"affected", value:"Sphinx Mobile Web Server U3 3.1.2.47 and prior.");
  script_tag(name:"insight", value:"The flaws are due to an improper validation of user-supplied input
  via the 'comment' parameter to '/Blog/MyFirstBlog.txt' and
  '/Blog/AboutSomething.txt', which allows attacker to execute arbitrary HTML
  and script code on the user's browser session in the security context of an
  affected site.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running Sphinx Mobile Web Server and is prone to
  persistent cross site scripting vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

mwsPort = get_http_port(default:8080);

banner = get_http_banner(port: mwsPort);
if("Server: MobileWebServer/" >!< banner){
  exit(0);
}

pages = make_list("/MyFirstBlog.txt", "/AboutSomething.txt");

foreach page (pages)
{
  url1 = "/Blog" + page + "?comment=<script>alert(document.cookie)" +
                          "</script>&submit=Add+Comment";

  sndReq = http_get(item: url1, port:mwsPort);
  http_keepalive_send_recv(port:mwsPort, data:sndReq);

  url2 = "/Blog" + page ;

  if(http_vuln_check(port:mwsPort, url:url2, pattern:"<script>alert" +
                           "\(document.cookie\)</script>", check_header:TRUE))
  {
    report = report_vuln_url( port:mwsPort, url:url2);
    security_message(port:mwsPort, data:report);
    exit(0);
  }
}

exit(99);
