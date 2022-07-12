# OpenVAS Vulnerability Test
# $Id: mod_python_handle.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: mod_python handle abuse
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2002 Thomas Reinke
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
  script_oid("1.3.6.1.4.1.25623.1.0.10947");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(4656);
  script_cve_id("CVE-2002-0185");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("mod_python handle abuse");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Thomas Reinke");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl", "no404.nasl");
  script_mandatory_keys("mod_python/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Upgrade to a newer version.");

  script_tag(name:"summary", value:"The remote host is using the Apache mod_python module which
  is version 2.7.6 or older.

  These versions allow a module which is indirectly imported
  by a published module to then be accessed via the publisher,
  which allows remote attackers to call possibly
  dangerous functions from the imported module.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner || "mod_python" >!< banner)
  exit(0);

serv = strstr(banner, "Server");
if(ereg(pattern:".*mod_python/(1.*|2\.([0-6]\..*|7\.[0-6][^0-9])).*", string:serv)) {
  security_message(port:port);
  exit(0);
}

exit(99);