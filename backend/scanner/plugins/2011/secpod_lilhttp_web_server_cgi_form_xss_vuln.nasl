###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_lilhttp_web_server_cgi_form_xss_vuln.nasl 13681 2019-02-15 08:41:57Z mmartin $
#
# LilHTTP Server 'CGI Form Demo' Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902437");
  script_version("$Revision: 13681 $");
  script_cve_id("CVE-2002-1009");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:41:57 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Lil' HTTP Server Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101758/lilhttp-xss.txt");
  script_xref(name:"URL", value:"http://www.securityhome.eu/exploits/exploit.php?eid=5477687364de02d6a4c2430.52315196");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("LilHTTP/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to plant XSS
  backdoors and inject arbitrary SQL statements via crafted XSS payloads.");

  script_tag(name:"affected", value:"LilHTTP Server version 2.2 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input,
  passed in the 'name' and 'email' parameter in 'cgitest.html', when handling the
  'CGI Form Demo' application.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running LilHTTP Web Server and is prone to cross site
  scripting vulnerability");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

lilPort = get_http_port(default:80);
banner = get_http_banner(port:lilPort);
if(!banner || "Server: LilHTTP" >!< banner)
  exit(0);

postdata = "name=%3Cscript%3Ealert%28%27VT-XSS-TEST%27%29%3C%2Fscript%3E&email=";

url = "/pbcgi.cgi";

useragent = http_get_user_agent();
host = http_host_name(port:lilPort);

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Length: ", strlen(postdata), "\r\n",
             "\r\n", postdata);
res = http_keepalive_send_recv(port:lilPort, data:req);

if(res =~ "^HTTP/1\.[01] 200" && "name=<script>alert('VT-XSS-TEST')</script>" >< res){
  report = report_vuln_url(port:lilPort, url:url);
  security_message(port:lilPort, data:report);
  exit(0);
}

exit(99);