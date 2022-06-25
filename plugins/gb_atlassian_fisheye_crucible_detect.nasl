###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atlassian_fisheye_crucible_detect.nasl 10890 2018-08-10 12:30:06Z cfischer $
#
# Atlassian FishEye and Crucible Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140326");
  script_version("$Revision: 10890 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:30:06 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-08-25 14:18:37 +0700 (Fri, 25 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Atlassian FishEye and Crucible Detection");

  script_tag(name:"summary", value:"Detection of Atlassian FishEye and Crucible.

The script sends a connection request to the server and attempts to detect Atlasian FishEye and Crucible and to
extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.atlassian.com/software/fisheye");
  script_xref(name:"URL", value:"https://www.atlassian.com/software/crucible");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

foreach dir (make_list_unique("/", "/crucible", "/fisheye", cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/");

  if (('display-name="FishEye and Crucible"' >< res || "<title>Log in to FishEye and Crucible" >< res) &&
      res =~ "Page generated [0-9]{4}-") {
    version = "unknown";

    vers = eregmatch(pattern: "\(Version:([0-9.]+)", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "atlassian_fisheye_crucible/version", value: version);
    }

    set_kb_item(name: "atlassian_fisheye_crucible/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:atlassian:fisheye:");
    if (!cpe)
      cpe = 'cpe:/a:atlassian:fisheye';

    cpe2 =  build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:atlassian:crucible:");
    if (!cpe)
      cpe = 'cpe:/a:atlassian:crucible';

    register_product(cpe: cpe, location: install, port: port);
    register_product(cpe: cpe2, location: install, port: port);

    log_message(data: build_detection_report(app: "Atlassian FishEye and Crucible", version: version,
                                             install: install, cpe: cpe, concluded: vers[0]),
                port: port);
    exit(0);
  }
}

exit(0);
