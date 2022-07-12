###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_artifectx_xclassified_sql_inj_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# Artifectx xClassified 'catid' SQL Injection Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804684");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2014-4741");
  script_bugtraq_id(68438);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-07-21 11:57:35 +0530 (Mon, 21 Jul 2014)");
  script_name("Artifectx xClassified 'catid' SQL Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Artifectx xClassified and is prone to sql injection
  vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it is able to execute
  sql query or not.");
  script_tag(name:"insight", value:"Flaw is due to the 'ads.php' script not properly sanitizing user-supplied input
  to the 'catid' parameter.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to manipulate SQL queries in the
  backend database allowing for the manipulation or disclosure of arbitrary data.");
  script_tag(name:"affected", value:"Artifectx XClassified version 1.2");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127370");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

foreach dir (make_list_unique("/", "/ads", "/classifieds", "/artifectx", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"),  port:http_port);

  if (">xClassified Web" >< rcvRes && "artifectx" >< rcvRes)
  {
    url = dir + "/ads.php?catid=1'SQL-Injection-Test" ;

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"SQL-Injection-Test",
       extra_check: make_list("Artifectx", ">Login<")))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
