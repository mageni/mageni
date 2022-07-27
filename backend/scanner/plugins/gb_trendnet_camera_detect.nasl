###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trendnet_camera_detect.nasl 13795 2019-02-20 15:20:14Z cfischer $
#
# Trendnet Internet Camera Detection
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.112337");
  script_version("$Revision: 13795 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-20 16:20:14 +0100 (Wed, 20 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-07-25 13:49:11 +0200 (Wed, 25 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Trendnet Internet Camera Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Trendnet Internet Camera devices.");

  script_xref(name:"URL", value:"https://www.trendnet.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");

CPE = "cpe:/h:trendnet:ip_camera:";

port = get_http_port(default: 80);
banner = get_http_banner(port:port);

if(banner && banner =~ 'www-authenticate:[ ]?basic[ ]?realm="netcam') {

  set_kb_item(name: "trendnet/ip_camera/detected", value: TRUE);
  set_kb_item(name: "trendnet/ip_camera/http_port", value: port);

  version = "unknown";

  register_and_report_cpe(app: "Trendnet IP Camera", ver: version, base: CPE, expr: "([^0-9.]+)", insloc: "/", regPort: port);
  exit(0);
}

exit(0);