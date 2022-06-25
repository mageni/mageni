###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sphider_mult_sql_inj_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# Sphider Multiple Vulnerabilities - Aug14
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
  script_oid("1.3.6.1.4.1.25623.1.0.804737");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2014-5082", "CVE-2014-5192", "CVE-2014-5193");
  script_bugtraq_id(69019, 68985);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-08-25 13:06:02 +0530 (Mon, 25 Aug 2014)");
  script_name("Sphider Multiple Vulnerabilities - Aug14");

  script_tag(name:"summary", value:"This host is installed with Sphider and is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to
  execute sql query or not.");
  script_tag(name:"insight", value:"Flaw is due to the /sphider/admin/admin.php script not properly sanitizing
  user-supplied input to the 'site_id', 'url', 'filter', and 'category'
  parameters.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code and SQL statements on the vulnerable system, which may lead to
  access or modify data in the underlying database.");
  script_tag(name:"affected", value:"Sphider version 1.3.6 and earlier");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34238");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127720");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
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

host = http_host_name(port:http_port);

foreach dir (make_list_unique("/", "/sphider", "/search", "/webspider", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/admin/admin.php"),  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if(">Sphider" >< rcvRes)
  {
    url = dir + '/admin/admin.php';

    postData = "user=foo&pass=bar&f=20&site_id=1'SQL-Injection-Test";

    sndReq = string("POST ", url, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(postData), "\r\n",
                    "\r\n", postData);

    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq, bodyonly:TRUE);

    if(rcvRes && rcvRes =~ "You have an error in your SQL syntax.*SQL-Injection-Test")
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);