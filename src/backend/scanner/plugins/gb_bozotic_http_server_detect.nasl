###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bozotic_http_server_detect.nasl 14165 2019-03-14 06:59:37Z cfischer $
#
# bozotic HTTP server Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801244");
  script_version("$Revision: 14165 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 07:59:37 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("bozotic HTTP server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("bozohttpd/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"This script finds the running bozotic HTTP server version and saves
  the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(! banner || "erver: bozohttpd" >!< banner)
  exit(0);

version = "unknown";
ver = eregmatch(pattern:"bozohttpd/([0-9.]+)", string:banner);
if(ver[1])
  version = ver[1];

set_kb_item(name:"bozohttpd/detected", value:TRUE);

register_and_report_cpe(app:"bozotic HTTP server", ver:version, concluded:ver[0], regService:"www", regPort:port, base:"cpe:/a:eterna:bozohttpd:", expr:"^([0-9.]+)", insloc:port + "/tcp");

exit(0);