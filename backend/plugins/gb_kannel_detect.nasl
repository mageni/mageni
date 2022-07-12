###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kannel_detect.nasl 10922 2018-08-10 19:21:48Z cfischer $
#
# Kannel WAP/SMS Gateway Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.140385");
  script_version("$Revision: 10922 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 21:21:48 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-09-21 14:31:53 +0700 (Thu, 21 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Kannel WAP/SMS Gateway Detection");

  script_tag(name:"summary", value:"Detection of Kannel WAP/SMS Gateway.

The script sends a connection request to the server and attempts to detect Kannel WAP/SMS Gateway and to extract
its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Kannel/banner");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.kannel.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");


port = get_http_port(default: 80);

banner = get_http_banner(port: port);

if (egrep(pattern: "Kannel/", string: banner)) {
  version = "unknown";

  vers = eregmatch(pattern: "Server: Kannel/([0-9svnr.-]+)", string: banner);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "kannel/version", value: version);
  }

  set_kb_item(name: "kannel/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9svnr.-]+)", base: "cpe:/a:kannel:kannel:");
  if (!cpe)
    cpe = 'cpe:/a:kannel:kannel';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Kannel", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
