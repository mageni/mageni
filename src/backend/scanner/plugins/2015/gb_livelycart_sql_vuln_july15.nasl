###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_livelycart_sql_vuln_july15.nasl 11452 2018-09-18 11:24:16Z mmartin $
#
# LivelyCart SQL Injection Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805671");
  script_version("$Revision: 11452 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 13:24:16 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-07-06 10:15:48 +0530 (Mon, 06 Jul 2015)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("LivelyCart SQL Injection Vulnerability");

  script_tag(name:"summary", value:"The host is installed with LivelyCart and
  is prone to sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"The flaw exists due to the 'search_query'
  parameter in 'product/search' script is not filtering user supplied data.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary SQL commands.");

  script_tag(name:"affected", value:"LivelyCart version 1.2.0");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37325");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

livPort = get_http_port(default:80);
if(!can_host_php(port:livPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/livcart", "/cart",  cgi_dirs(port:livPort)))
{

  if( dir == "/" ) dir = "";

  sndReq = http_get(item:string(dir,"/auth/login"), port:livPort);
  rcvRes = http_keepalive_send_recv(port:livPort, data:sndReq);

  if("Powered by LivelyCart" >< rcvRes)
  {
    url = dir + "/product/search?search_query='";

    if(http_vuln_check(port:livPort, url:url, check_header:FALSE,
                       pattern:"You have an error in your SQL syntax"))
    {
      security_message(port:livPort);
      exit(0);
    }
  }
}

exit(99);
