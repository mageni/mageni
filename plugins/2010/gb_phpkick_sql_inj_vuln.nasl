##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpkick_sql_inj_vuln.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# PHPKick 'statistics.php' SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801431");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-08-19 10:23:11 +0200 (Thu, 19 Aug 2010)");
  script_cve_id("CVE-2010-3029");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHPKick 'statistics.php' SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14578/");
  script_xref(name:"URL", value:"http://securityreason.com/exploitalert/8639");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaw exists due to an error in 'statistics.php', which fails
  to properly sanitise input data passed via the 'gameday' parameter in overview action.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running PHPKick and is prone SQL injection
  vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to view, add, modify
  or delete information in the back-end database.");
  script_tag(name:"affected", value:"PHPKick version 0.8");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

phpPort = get_http_port(default:80);

if(!can_host_php(port:phpPort)){
  exit(0);
}

foreach dir (make_list_unique("/phpkick", "/PHPKick", "/", cgi_dirs(port:phpPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:phpPort);

  if("<TITLE>PHPKick</TITLE>" >< rcvRes)
  {
    sndReq = http_get(item:string(dir, "/statistics.php?action=overview" +
                           "&gameday=,"), port:phpPort);
    rcvRes = http_keepalive_send_recv(port:phpPort, data:sndReq);

    if("SQL syntax;" >< rcvRes && "MySQL server" >< rcvRes)
    {
      security_message(port:phpPort);
      exit(0);
    }
  }
}

exit(99);