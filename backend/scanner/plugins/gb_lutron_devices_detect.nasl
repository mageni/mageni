###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lutron_devices_detect.nasl 8984 2018-02-28 15:13:41Z cfischer $
#
# Lutron Devices Remote Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812952");
  script_version("$Revision: 8984 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-02-28 16:13:41 +0100 (Wed, 28 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-27 16:58:19 +0530 (Tue, 27 Feb 2018)");
  script_name("Lutron Devices Remote Detection");

  script_tag(name:"summary", value:"Detection of Lutron Devices.

  The script sends a connection request to the server and attempts to detect the
  presence of Lutron Devices.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

lutPort = get_http_port(default:80);

res = http_get_cache(port:lutPort, item:"/");
if("<h1>LUTRON</h1>" >< res && 'name="login"' >< res && 'name="password"')
{
  version = "unknown";

  set_kb_item(name:"lutron/detected", value:TRUE);

  cpe = 'cpe:/a:lutron:device';

  register_product( cpe:cpe, location:"/", port:lutPort,  service:"www");
  log_message(data: build_detection_report(app: "LutPort Device", version:version, install: "/", cpe: cpe,
                                           concluded: "LutPort Device Detected"),
                                           port: lutPort);
  exit(0) ;
}
exit( 0 );
