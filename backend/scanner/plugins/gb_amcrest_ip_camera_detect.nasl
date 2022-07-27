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
  script_oid("1.3.6.1.4.1.25623.1.0.114084");
  script_version("$Revision: 14333 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:24:22 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-15 14:31:11 +0100 (Fri, 15 Mar 2019)");
  script_name("Amcrest Technologies IP Camera Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installation of
  Amcrest's IP Camera software.

  This script sends HTTP GET request and try to ensure the presence of
  the Amcrest IP Camera web interface.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

#Note: This software is very similar to Dahua's -> gb_dahua_devices_detect.nasl and related VTs

port = get_http_port(default: 8080);

url = "/custom_lang/English.txt";

res = http_get_cache(port: port, item: url);

if(res =~ "Copyright\s*[0-9]+\s*Amcrest\s*Technologies" && "w_camera_info" >< res) {

  #Version detection requires login.
  version = "unknown";

  set_kb_item(name: "amcrest/ip_camera/detected", value: TRUE);
  set_kb_item(name: "amcrest/ip_camera/" + port + "/detected", value: TRUE);

  cpe = "cpe:/a:amcrest:ip_camera:";

  conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "Amcrest Technologies IP Camera",
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
