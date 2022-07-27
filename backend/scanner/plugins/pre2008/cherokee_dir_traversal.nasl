# OpenVAS Vulnerability Test
# Description: Cherokee directory traversal flaw
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
  script_oid("1.3.6.1.4.1.25623.1.0.15621");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_cve_id("CVE-2001-1432");
  script_bugtraq_id(3772);
  script_name("Cherokee directory traversal flaw");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Gain a shell remotely");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Cherokee/banner");
  script_require_ports("Services/www", 443);

  script_tag(name:"solution", value:"Upgrade to Cherokee 0.2.8 or newer.");

  script_tag(name:"summary", value:"The remote version of Cherokee is vulnerable to directory
  traversal flaw when appending a '../' sequence to the web request.

  Additionally, this version fails to drop root privileges after it binds
  to listen port.");

  script_tag(name:"impact", value:"Remote attacker can then submit specially crafted web request to
  browse any file on the server with root privileges.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner || "Cherokee" >!< banner)
  exit(0);

serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Cherokee/0\.([01]\.|2\.[0-7])[^0-9]", string:serv)) {
  security_message(port:port);
  exit(0);
}

exit(99);