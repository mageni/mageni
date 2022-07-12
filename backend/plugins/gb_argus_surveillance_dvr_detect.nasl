###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_argus_surveillance_dvr_detect.nasl 11155 2018-08-29 09:07:04Z ckuersteiner $
#
# Argus Surveillance DVR Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.141408");
  script_version("$Revision: 11155 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-29 11:07:04 +0200 (Wed, 29 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-29 13:32:59 +0700 (Wed, 29 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Argus Surveillance DVR Detection");

  script_tag(name:"summary", value:"Detection of Argus Surveillance DVR.

The script sends a connection request to the server and attempts to detect Argus Surveillance DVR and to extract
its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.argussurveillance.com//");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8080);

url = "/About.html";
res = http_get_cache(port: port, item: url);

if ("<B>Argus Surveillance DVR</B>" >< res && "MotionAndEvents.html" >< res) {
  version = "unknown";

  vers = eregmatch(pattern: "Version: <B>([0-9.]+)<", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = url;
  }

  set_kb_item(name: "argus_surveillance/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:argus_surveillance:dvr:");
  if (!cpe)
    cpe = 'cpe:/a:argus_surveillance:dvr';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Argus Surveillance DVR", version: version, install: "/",
                                           cpe: cpe, concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
