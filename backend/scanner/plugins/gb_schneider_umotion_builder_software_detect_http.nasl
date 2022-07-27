###############################################################################
# OpenVAS Vulnerability Test
#
# Schneider Electric U.motion Builder Software Detection (HTTP)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, https://www.greenbone.net
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.107448");
  script_version("2019-05-16T06:13:05+0000");
  script_tag(name:"last_modification", value:"2019-05-16 06:13:05 +0000 (Thu, 16 May 2019)");
  script_tag(name:"creation_date", value:"2019-01-12 15:02:54 +0100 (Sat, 12 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Schneider Electric U.motion Builder Software Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Schneider Electric U.motion Builder Software

  The script sends a HTTP connection request to the server and attempts to detect Schneider Electric U.motion
  Builder Softwaret and to extract its version.");

  script_xref(name:"URL", value:"https://www.schneider-electric.com/en/product-range/61124-u.motion/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8080);

url = "/umotion/modules/system/externalframe.php?context=runtime";
buf = http_get_cache(item: url, port: port);

if ('U.motion</title>' >< buf && 'U.motion Control' >< buf) {
  version = "unknown";

  vers = eregmatch(pattern: '"version":"([0-9.]+)"', string: buf);
  if (!isnull(vers[1])) {
    version = vers[1];
    conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  set_kb_item(name: "schneider/umotion_builder/detected", value: TRUE);

  register_and_report_cpe(app: "Schneider Electric U.motion Builder Software", ver: version,
                          base: "cpe:/a:schneider:umotion_builder:", expr: "^([0-9.]+)", insloc: "/umotion",
                          regPort: port, concluded: vers[0], conclUrl: conclUrl, regService: "www");
  exit(0);
}

exit(0);
