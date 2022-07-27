###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_maygion_ipcamera_detect.nasl 13794 2019-02-20 14:59:32Z cfischer $
#
# MayGion IPCamera Detection
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.114062");
  script_version("$Revision: 13794 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-20 15:59:32 +0100 (Wed, 20 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-04 15:56:53 +0100 (Mon, 04 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MayGion IPCamera Detection");

  script_tag(name:"summary", value:"Detection of MayGion IPCamera.

  The script sends a connection request to the server and attempts to detect the web interface for MayGion IPCamera.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 81);
  script_mandatory_keys("WebServer_IPCamera_Logo/banner");

  script_xref(name:"URL", value:"https://elinux.org/MayGion_MIPS_IPCam");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");

port = get_http_port(default: 81);
banner = get_http_banner(port: port);

if(banner && "Server: WebServer(IPCamera_Logo)" >< banner){
  version = "unknown";
  install = "/";

  conclUrl = report_vuln_url(port: port, url: "/", url_only: TRUE);
  cpe = "cpe:/a:maygion:ip_camera:";

  set_kb_item(name: "maygion/ip_camera/detected", value: TRUE);
  set_kb_item(name: "maygion/ip_camera/" + port + "/detected", value: TRUE);

  register_and_report_cpe(app: "MayGion IPCamera",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: install,
                          regPort: port,
                          regService: "www",
                          conclUrl: conclUrl,
                          extra: "Version detection requires login.");
}

exit(0);