###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_literadius_mult_sql_vuln.nasl 11987 2018-10-19 11:05:52Z mmartin $
#
# LiteRadius Multiple SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802121");
  script_version("$Revision: 11987 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 13:05:52 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-15 12:23:42 +0200 (Fri, 15 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("LiteRadius Multiple SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17528/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103018/literadius-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive
  information by injecting arbitrary SQL code.");
  script_tag(name:"affected", value:"LiteRadius version 3.2 and prior.");
  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input
  via the 'lat' and 'long' parameters in 'locator.php', which allows attackers to
  manipulate SQL queries by injecting arbitrary SQL code.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running LiteRadius and is prone to multiple SQL
  injection vulnerabilities.");

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

foreach dir (make_list_unique("/dealers", "/literadius", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: string (dir, "/index.php"), port:port);

  if('<title>Dealer Locator' >< res || '<title>LiteRadius' >< res)
  {
    sndReq = http_get(item:string(dir, "/locator.php?parsed_page=1&lat=25.4405"+
                                  "436315&long=132.710253334'"), port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

    if(("failed SELECT sqrt(power" >< rcvRes) && ("* FROM" >< rcvRes))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);