###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simplehrm_username_sql_inj_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# SimpleHRM 'username' Parameter SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.804531");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2013-2498");
  script_bugtraq_id(59254);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-04-03 10:35:41 +0530 (Thu, 03 Apr 2014)");
  script_name("SimpleHRM 'username' Parameter SQL Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with SimpleHRM and is prone to sql injection
  vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it is able to execute
  sql query or not.");
  script_tag(name:"insight", value:"Flaw is due to the /index.php/user/setLogin script not properly sanitizing
  user-supplied input to the 'username' parameter.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to manipulate SQL queries in the
  backend database allowing for the manipulation or disclosure of arbitrary data.");
  script_tag(name:"affected", value:"SimpleHRM version 2.3 and 2.2, Other versions may also be affected.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24954");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/04/17/1");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"WillNotFix");
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

foreach dir (make_list_unique("/", "/simplehrm", "/hrm", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"),  port:http_port);

  if("SimpleHRM<" >< rcvRes)
  {
    url = dir + "/index.php/user/setLogin";

    postData = 'username=%27SQL-Injection-Test&password=abcdef';

    sndReq = string("POST ", url, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(postData), "\r\n",
                    "\r\n", postData, "\r\n");

    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq, bodyonly:TRUE);

    if(rcvRes && rcvRes =~ "Execute Error: You have an error in your SQL syntax.*SQL-Injection-Test"
              && ">SimpleHRM" >< rcvRes)
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
