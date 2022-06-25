###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_parsp_shopping_cms_mult_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# Parsp Shopping CMS Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802575");
  script_version("$Revision: 11374 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-02-01 15:28:20 +0530 (Wed, 01 Feb 2012)");
  script_name("Parsp Shopping CMS Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://1337day.com/exploits/17418");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18409/");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2012010198");
  script_xref(name:"URL", value:"http://www.exploitsdownload.com/search/Arab");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108953/parspshoppingcms-xssdisclose.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  web script or HTML in a user's browser session in the context of an affected
  site and gain th sensitive information related to PHP.");
  script_tag(name:"affected", value:"Parsp Shopping CMS version V5 and prior.");
  script_tag(name:"insight", value:"The flaws are due to an,

  - Input passed to the 'advanced_search_in_category' parameter in 'index.php'
   is not properly sanitised before being returned to the user.

  - Error in 'phpinfo.php' script, this can be exploited to gain knowledge
   of sensitive information by requesting the file directly.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Parsp Shopping CMS and is prone to multiple
  vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/parsp", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:port);

  if(egrep(pattern:'>powered by .*>www.parsp.com<', string:rcvRes))
  {
    ## Attack to obtain information about php
    sndReq = http_get(item: dir + "/phpinfo.php", port:port);
    rcvRes = http_keepalive_send_recv(port:port,data:sndReq);

    if("<title>phpinfo" >< rcvRes && ">PHP Core<" >< rcvRes)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
