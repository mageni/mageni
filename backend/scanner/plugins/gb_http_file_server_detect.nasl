###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_http_file_server_detect.nasl 10915 2018-08-10 15:50:57Z cfischer $
#
# Http File Server Version Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806812");
  script_version("$Revision: 10915 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:50:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-01-05 17:56:58 +0530 (Tue, 05 Jan 2016)");
  script_name("Http File Server Version Detection");

  script_tag(name:"summary", value:"Detection of installed version
  of Http file server.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("HFS/banner");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if("erver: HFS" >!< banner) {
  exit(0);
}

version = "unknown";

## Match the version from banner
vers = eregmatch(pattern:"Server: HFS (([0-9.])+([a-z]+)?)", string:banner, icase:TRUE);
if( ! isnull(vers[1])) version = vers[1];

set_kb_item(name:"hfs/Installed", value:TRUE);

cpe = build_cpe(value:vers[1], exp:"^([0-9.a-z]+)", base:"cpe:/a:httpfilesever:hfs:");
if(!cpe)
  cpe= "cpe:/a:httpfilesever:hfs";

register_product(cpe:cpe, location:"/", port:port);

log_message(data: build_detection_report(app: "Http File Server",
                                         version: version,
                                         install: "/",
                                         cpe: cpe,
                                         concluded: vers[0]),
                                         port: port);
exit(0);
