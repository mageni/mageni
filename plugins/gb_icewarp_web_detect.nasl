###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_icewarp_web_detect.nasl 10915 2018-08-10 15:50:57Z cfischer $
#
# IceWarp Web Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.140329");
  script_version("$Revision: 10915 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:50:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-08-28 14:59:29 +0700 (Mon, 28 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IceWarp Web Detection");

  script_tag(name:"summary", value:"Detection of IceWarp Web UI.

The script sends a connection request to the server and attempts to detect IceWarp Web UI and to
extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("IceWarp/banner");

  script_xref(name:"URL", value:"http://www.icewarp.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");


port = get_http_port(default: 80);

banner = get_http_banner(port: port);

if (egrep(pattern: "IceWarp/", string: banner)) {
  version = "unknown";

  vers = eregmatch(pattern: "IceWarp/([0-9.]+)", string: banner);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "icewarp/version", value: version);
  }

  set_kb_item(name: "icewarp/installed", value: TRUE);
  set_kb_item(name: "icewarp/web/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:icewarp:mail_server:");
  if (!cpe)
    cpe = 'cpe:/a:icewarp:mail_server';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "IceWarp", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
