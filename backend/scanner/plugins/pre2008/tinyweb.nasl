# OpenVAS Vulnerability Test
# $Id: tinyweb.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: TinyWeb 1.9
#
# Authors:
# Matt North
#
# Copyright:
# Copyright (C) 2003 Matt North
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
  script_oid("1.3.6.1.4.1.25623.1.0.11894");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2003-1510");
  script_bugtraq_id(8810);
  script_name("TinyWeb 1.9");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Matt North");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("TinyWeb/banner");

  script_tag(name:"solution", value:"Contact the Vendor for an update.");

  script_tag(name:"summary", value:"The remote host is running TinyWeb version 1.9 or older.");

  script_tag(name:"impact", value:"A remote user can issue an HTTP GET request for
  /cgi-bin/.%00./dddd.html and cause the server consume large amounts of CPU time (88%-92%).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
banbanner = get_http_banner(port:port);
if(!banner || "TinyWeb" >!< banner)
  exit(0);

if(egrep(pattern:"^Server:.*TinyWeb/(0\..*|1\.[0-9]([^0-9]|$))", string:banner)) {
  security_message(port:port);
  exit(0);
}

exit(99);