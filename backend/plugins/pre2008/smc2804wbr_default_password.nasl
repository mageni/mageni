# OpenVAS Vulnerability Test
# $Id: smc2804wbr_default_password.nasl 14336 2019-03-19 14:53:10Z mmartin $
# Description: SMC2804WBR Default Password
#
# Authors:
# Audun Larsen <larsen@xqus.com>
#
# Copyright:
# Copyright (C) 2004 Audun Larsen
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12069");
  script_version("$Revision: 14336 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:53:10 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("SMC2804WBR Default Password");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2004 Audun Larsen");
  script_family("Privilege escalation");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name:"solution", value:"Change the administrator password");
  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"summary", value:"The remote host is a SMC2804WBR access point.

 This host is installed with a default administrator
 password (smcadmin) which has not been modified.");
  script_tag(name:"impact", value:"An attacker may exploit this flaw to gain control over
 this host using the default password.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);
res = http_get_cache(item:"/", port:port);
if( res == NULL ) exit(0);
if("SMC2804WBR" >< res && "Please enter correct password for Administrator Access. Thank you." >< res)
{

  host = http_host_name( port:port );
  variables = string("page=login&pws=smcadmin");
  req = string("POST /login.htm HTTP/1.1\r\n",
  	      "Host: ", host, "\r\n",
	      "Content-Type: application/x-www-form-urlencoded\r\n",
	      "Content-Length: ", strlen(variables), "\r\n\r\n", variables);

  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);
  if("<title>LOGIN</title>" >!< buf)
  {
   security_message(port:port);
   exit(0);
  }
}

exit(99);
