###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webdepo_cms_sql_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# WebDepo CMS 'wood' Parameter SQL Injection Vulnerability
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805374");
  script_version("$Revision: 11872 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-04-23 17:22:49 +0530 (Thu, 23 Apr 2015)");
  script_name("WebDepo CMS 'wood' Parameter SQL Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with WebDepo CMS and
  is prone to sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Flaw is due to the 'text.asp' script not
  properly sanitizing user-supplied input to the 'wood' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"WebDepo CMS");

  script_tag(name:"solution", value:"As a workaround sanitize all requests coming
  from the client.");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"Workaround");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Mar/156");
  script_xref(name:"URL", value:"http://blog.inurl.com.br/2015/03/0day-webdepo-sql-injection.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.webdepot.co.il");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

cmsPort = get_http_port(default:80);
if(!can_host_asp(port:cmsPort))exit(0);

foreach dir (make_list_unique("/", "/webdepot", "/webdepo",  cgi_dirs(port:cmsPort)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:dir + "/",  port:cmsPort);

  if (rcvRes && "webdepot<" >< rcvRes)
  {
    url = dir + "/text.asp?wood=12'";

    sndReq = http_get(item:url,  port:cmsPort);
    rcvRes = http_keepalive_send_recv(port:cmsPort, data:sndReq);

    if(rcvRes && ("You have an error in your SQL syntax" >< rcvRes ||
                  "Microsoft JET Database Engine" >< rcvRes ||
                  "Microsoft VBScript runtime" >< rcvRes))
    {
     security_message(port:cmsPort);
     exit(0);
    }
  }
}

exit(99);
