# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114082");
  script_version("$Revision: 14189 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 15:17:23 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-14 13:23:37 +0100 (Thu, 14 Mar 2019)");
  script_name("GW Security IP Camera Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installation of
  GW Security's IP Camera software.

  This script sends HTTP GET request and try to ensure the presence of
  the GW Security IP Camera web interface.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

#Note: This software is a bit similar to Hikvision's, detected by gb_hikvision_ip_camera_detect.nasl

port = get_http_port(default: 80);

url1 = "/doc/xml/en/Preview.xml";
url2 = "/doc/xml/en/Login.xml";

res1 = http_get_cache(port: port, item: url1);
res2 = http_get_cache(port: port, item: url2);

if("<laMainStream>Record Bitrate</laMainStream>" >< res1 && "<laSubStream>Network Bitrate</laSubStream>" >< res1
  && "<LoginTips1>Please" >< res2 && "<LoginTips2>User name cannot be longer than 16 characters.</LoginTips2>" >< res2) {

  #Version detection requires login.
  version = "unknown";

  set_kb_item(name: "gw_security/ip_camera/detected", value: TRUE);
  set_kb_item(name: "gw_security/ip_camera/" + port + "/detected", value: TRUE);

  cpe = "cpe:/a:gw_security:ip_camera:";

  conclUrl = report_vuln_url(port: port, url: url2, url_only: TRUE);

  register_and_report_cpe(app: "GW Security IP Camera",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: "/",
                          regPort: port,
                          regService: "www",
                          conclUrl: conclUrl,
                          extra: "Version detection requires login.");
}

exit(0);
