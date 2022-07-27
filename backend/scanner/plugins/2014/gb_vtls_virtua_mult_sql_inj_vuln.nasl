###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vtls_virtua_mult_sql_inj_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# vtls-Virtua 'InfoStation.cgi' Multiple SQL Injection Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804759");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-2081");
  script_bugtraq_id(69413);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-08-27 13:21:53 +0530 (Wed, 27 Aug 2014)");
  script_name("vtls-Virtua 'InfoStation.cgi' Multiple SQL Injection Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with vtls-Virtua and is prone to multiple sql injection
  vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to
  execute sql query or not.");
  script_tag(name:"insight", value:"Flaw is due to the /web_reports/cgi-bin/InfoStation.cgi script not properly
  sanitizing user-supplied input to the 'username' and 'password' parameters.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code and SQL statements on the vulnerable system, which may leads to
  access or modify data in the underlying database.");
  script_tag(name:"affected", value:"vtls-Virtua version 2014.X and 2013.2.X");
  script_tag(name:"solution", value:"Upgrade to version 2014.1.1 or 2013.2.4 or later.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127997");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Aug/64");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.vtls.com/products/vtls-virtua");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

if(!can_host_php(port:http_port)){
  exit(0);
}

host = http_host_name(port:http_port);

foreach dir (make_list_unique("/", "/virtua", "/vlts", "/mgmt", "/libmgmt", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  url = dir + "/web_reports/cgi-bin/InfoStation.cgi?mod=login&func=login&lang_code=en";

  sndReq = http_get(item:url,  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if("Virtua<" >< rcvRes && ">InfoStation - Log In<" >< rcvRes)
  {
    postData = "mod=login&func=process&database=1&lang_code=en&report_group" +
               "=Adm&filter=test&username=%27SQL-Injection-Test&password=%27";

    sndReq = string("POST ", url, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(postData), "\r\n",
                    "\r\n", postData);

    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq, bodyonly:TRUE);

    if(rcvRes && rcvRes =~ "SQL error.*SQL command not properly ended.*SQL-Injection-Test")
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);