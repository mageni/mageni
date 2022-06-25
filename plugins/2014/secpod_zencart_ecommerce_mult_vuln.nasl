###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_zencart_ecommerce_mult_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# Zen-cart E-commerce Multiple Vulnerabilities Feb-2014
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903513");
  script_version("$Revision: 11402 $");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-02-25 13:05:23 +0530 (Tue, 25 Feb 2014)");
  script_name("Zen-cart E-commerce Multiple Vulnerabilities Feb-2014");

  script_tag(name:"summary", value:"The host is running Zen-cart and is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
  is vulnerable or not.");
  script_tag(name:"insight", value:"The flaw are due to an,

  - Error which fails to sanitize 'redirect' parameter properly.

  - Insufficient validation of user-supplied input via the multiple POST
  parameters to multiple pages.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site and also can conduct phishing attacks.");
  script_tag(name:"affected", value:"Zen-cart version 1.5.1.");
  script_tag(name:"solution", value:"Vendor fixes are available.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125383/zencart151-shellxss.txt");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/zen-cart-e-commerce-151-xss-open-redirect-shell-upload");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

zcPort = get_http_port(default:80);

if(!can_host_php(port:zcPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/zencart", "/cart", cgi_dirs(port:zcPort)))
{

  if(dir == "/") dir = "";

  zenRes = http_get_cache(item:string(dir, "/index.php"), port:zcPort);

  if(zenRes && (egrep(pattern:"Powered by.*Zen Cart<", string:zenRes)))
  {
    url = dir + "/index.php?main_page=redirect&action=url&goto=www." +
            "example.com" ;
    ##Send the exploit
    zenReq = http_get(item:url, port:zcPort);
    zenRes = http_keepalive_send_recv(port:zcPort, data:zenReq, bodyonly:FALSE);

    if(zenRes && zenRes =~ "HTTP/1.. 302" && "Location: http://www.example.com" >< zenRes)
    {
      security_message(port:zcPort);
      exit(0);
    }
  }
}

exit(99);
