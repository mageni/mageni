###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tornado_cms_sql_inj_vuln.nasl 11452 2018-09-18 11:24:16Z mmartin $
#
# TORNADO Computer Trading CMS SQL Injection Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805565");
  script_version("$Revision: 11452 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 13:24:16 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-05-21 11:56:09 +0530 (Thu, 21 May 2015)");
  script_name("TORNADO Computer Trading CMS SQL Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with TORNADO CMS
  and is prone to sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able execute sql query or not.");

  script_tag(name:"insight", value:"Flaw exists as the input passed to
  'our_services.php', 'detail.php' and 'products.php' scripts via 'id' parameter
  is not properly sanitized before returning to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Tornado - Content Management System
  2015 Q2");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/131796");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/535465");
  script_xref(name:"URL", value:"http://www.vulnerability-lab.com/get_content.php?id=1489");

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

if(!can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/tornado", "/cms", "/tornadocms", cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"),  port:http_port);

  if(rcvRes =~ ">Website Designed & Developed By.*>Tornado<")
  {
    url = dir + "/products.php?category_id='SQL-INJECTION-TEST";

    if(http_vuln_check(port:http_port, url:url, check_header:FALSE,
       pattern:"You have an error in your SQL syntax",
       extra_check:"SQL-INJECTION-TEST"))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
