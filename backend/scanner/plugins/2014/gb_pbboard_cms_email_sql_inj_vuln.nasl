###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pbboard_cms_email_sql_inj_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# PBBoard CMS 'email' Parameter SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.805205");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2014-9215");
  script_bugtraq_id(71471);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-12-08 15:01:55 +0530 (Mon, 08 Dec 2014)");
  script_name("PBBoard CMS 'email' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35473");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/534149/30/0/threaded");
  script_xref(name:"URL", value:"http://www.itas.vn/news/ITAS-Team-discovered-SQL-Injection-in-PBBoard-CMS-68.html");

  script_tag(name:"summary", value:"This host is installed with PBBoard CMS
  and is prone to sql-injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Input passed via the 'email' POST parameter to
  the /includes/functions.class.php script is not properly sanitized before
  returning to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to inject or manipulate SQL queries in the back-end database allowing for the
  manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"PBBoard version 3.0.1 and prior.");

  script_tag(name:"solution", value:"Update to latest PBBoard version 3.0.1
  (updated on 28/11/2014) or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

if(!can_host_php(port:http_port)){
  exit(0);
}

host = http_host_name(port:http_port);

foreach dir (make_list_unique("/", "/PBBoard", "/pbb", "/forum", "/cms", cgi_dirs(port:http_port))){

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/Upload/index.php"),  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if (rcvRes && rcvRes =~ ">Powered by.*PBBoard<"){
    url = dir + "/Upload/index.php?page=register&checkemail=1";

    postData = "email='Sql-Injection-Test@f.com";

    sndReq = string("POST ", url, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded; charset=UTF-8", "\r\n",
                    "Referer: http://", get_host_name(), dir, "/Upload/index.php?page=register&index=1&agree=1","\r\n",
                    "Content-Length: ", strlen(postData), "\r\n\r\n",
                    postData, "\r\n");
    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

    if (rcvRes && "You have an error in your SQL syntax" >< rcvRes &&
                  "Sql-Injection-Test" >< rcvRes){
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);