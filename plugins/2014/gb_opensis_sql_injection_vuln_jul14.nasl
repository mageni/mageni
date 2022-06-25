###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opensis_sql_injection_vuln_jul14.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# openSIS 'index.php' SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.804653");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2014-8366");
  script_bugtraq_id(68285);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-07-04 10:45:35 +0530 (Fri, 04 Jul 2014)");
  script_name("openSIS 'index.php' SQL Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with openSIS and is prone to SQL injection
  vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request and check whether it is able to
  execute sql query or not.");
  script_tag(name:"insight", value:"Flaw is due to 'index.php' script which does not validate input via the
  'USERNAME' & 'PASSWORD' parameters before using in sql query.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary SQL
  statements on the vulnerable system, which may leads to access or modify data
  in the underlying database.");
  script_tag(name:"affected", value:"openSIS versions 4.5 and 5.3");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jun/151");
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

sisPort = get_http_port(default:80);

if(!can_host_php(port:sisPort)){
  exit(0);
}

host = http_host_name(port:sisPort);

foreach dir (make_list_unique("/", "/opensis", "/openSIS", cgi_dirs(port:sisPort)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item:string(dir, "/index.php"), port:sisPort);

  if(res && ">openSIS Student Information System<" >< res && ">User Name" >< res)
  {
    url = dir + "/index.php";
    postData = "USERNAME=%29+or+1%3D%28%271&PASSWORD=%27";

    req = string("POST ",url," HTTP/1.1\r\n",
                 "Host: ", host,"\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postData),"\r\n",
                 "\r\n",
                 postData);

    ## Send the crafted request and receive the response
    res = http_keepalive_send_recv(port:sisPort, data:req, bodyonly:TRUE);
    if(res && ">Database SQL error<" >< res &&
      ">SELECT MAX(SYEAR)" >< res)
    {
      security_message(port:sisPort);
      exit(0);
    }
  }
}

exit(99);