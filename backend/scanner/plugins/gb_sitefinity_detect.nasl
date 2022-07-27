###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sitefinity_detect.nasl 11717 2018-10-02 06:52:54Z ckuersteiner $
#
# Sitefinity CMS Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.140540");
  script_version("$Revision: 11717 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-02 08:52:54 +0200 (Tue, 02 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-28 08:24:34 +0700 (Tue, 28 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sitefinity Detection");

  script_tag(name:"summary", value:"Detection of Sitefinity CMS.

The script sends a connection request to the server and attempts to detect Sitefinity CMS and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.sitefinity.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

foreach dir (make_list_unique("/", cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/");

  if ('name="Generator" content="Sitefinity' >< res) {
    version = "unknown";

    vers = eregmatch(pattern: 'name="Generator" content="Sitefinity ([0-9.]+)', string: res);
    if (!isnull(vers[1]))
      version = vers[1];

    set_kb_item(name: "sitefinity/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:progress:sitefinity:");
    if (!cpe)
      cpe = 'cpe:/a:progress:sitefinity';

    register_product(cpe: cpe, location: install, port: port);

    log_message(data: build_detection_report(app: "Sitefinity", version: version, install: install, cpe: cpe,
                                             concluded: vers[0]),
                port: port);
    exit(0);
  }
}

exit(0);
