# OpenVAS Vulnerability Test
# $Id: cherokee_0_4_6.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Cherokee POST request DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.15620");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-1198");
  script_bugtraq_id(9345);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Cherokee POST request DoS");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Cherokee/banner");
  script_require_ports("Services/www", 443);

  script_tag(name:"solution", value:"Upgrade to Cherokee 0.4.7 or newer.");

  script_tag(name:"summary", value:"The remote version of tCherokee is vulnerable to remote denial
  of service vulnerability when handling a specially-crafted HTTP 'POST' request.");

  script_tag(name:"impact", value:"An attacker may exploit this flaw to disable this service remotely.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port: port);
if(!banner || "Cherokee" >!< banner)
  exit(0);

serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Cherokee/0\.([0-3]\.|4\.[0-6])[^0-9]", string:serv)) {
  security_message(port:port);
  exit(0);
}

exit(99);