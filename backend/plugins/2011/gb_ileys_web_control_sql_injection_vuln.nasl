###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ileys_web_control_sql_injection_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Ileys Web Control SQL Injection Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802315");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-05 09:04:20 +0200 (Fri, 05 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ileys Web Control SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://cryptr.org/printthread.php?tid=2278");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103372/ileys-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause SQL injection
  attack and gain sensitive information.");
  script_tag(name:"affected", value:"Ileys Web Control version 2.0");
  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  passed via the 'id' parameter in 'view.php', which allows attacker to manipulate
  SQL queries by injecting arbitrary SQL code.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Ileys Web Control and is prone to sql
  injection vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)) {
  exit(0);
}

foreach dir(make_list_unique("/", "/ileys", "/admin", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:port);

  if("Powered by:" >< rcvRes && "Ileys Web Control" >< rcvRes)
  {
    sndReq = http_get(item:string(dir, '/view.php?id=3333"'), port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

    if("You have an error in your SQL syntax;">< rcvRes)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);