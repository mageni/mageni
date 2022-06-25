###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netcat_cms_mul_vul.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# NetCat CMS Multiple Vulnerabilities
#
# Authors:
# Deependra Bapna <bdeepednra@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805346");
  script_version("$Revision: 11872 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-03 17:44:58 +0530 (Tue, 03 Mar 2015)");
  script_name("NetCat CMS Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with NetCat CMS
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP
  GET and check whether it redirects to the malicious website.");

  script_tag(name:"insight", value:"Multiple flaws are due to input
  passed via,

  - 'redirect_url' parameter to 'netshop/post.php' is not properly validated.

  - 'site' parameter to 'modules/redir/?' is not properly validated.

  - 'url' parameter to 'redirect.php?' is not properly validated.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to arbitrary URL redirection, disclosure or modification of sensitive
  data.");

  script_tag(name:"affected", value:"NetCat CMS version 5.01, 3.12, 3.0, 2.4,
  2.3, 2.2, 2.1, 2.0 and 1.1");

  script_tag(name:"solution", value:"Update to NetCat CMS 5.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Mar/8");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Mar/9");
  script_xref(name:"URL", value:"http://securityrelated.blogspot.in/2015/02/netcat-cms-multiple-url-redirection.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_xref(name:"URL", value:"http://netcat.ru");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

cmsPort = get_http_port(default:80);

foreach dir (make_list_unique("/", "/netcat", "/netcatcms", "/cms", cgi_dirs(port:cmsPort)))
{

  if( dir == "/" ) dir = "";
  rcvRes = http_get_cache(item:string(dir,"/"), port:cmsPort);

  if(">NetCat" >< rcvRes)
  {
    url = dir + '/modules/redir/?&site=http://www.example.com';

    sndReq = http_get(item:url, port:cmsPort);
    rcvRes = http_keepalive_send_recv(port:cmsPort, data:sndReq);

    if(rcvRes && rcvRes =~ "HTTP/1.. 302" &&
       rcvRes =~ "Location.*http://www.example.com")
    {
      security_message(port:cmsPort);
      exit(0);
    }
  }
}

exit(99);