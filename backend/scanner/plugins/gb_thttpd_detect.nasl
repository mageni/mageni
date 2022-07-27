###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_thttpd_detect.nasl 10890 2018-08-10 12:30:06Z cfischer $
#
# thttpd Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.140800");
  script_version("$Revision: 10890 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:30:06 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-02-23 10:46:04 +0700 (Fri, 23 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("thttpd Detection");

  script_tag(name:"summary", value:"Detection of thttpd.

The script sends a connection request to the server and attempts to detect thttpd and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("thttpd/banner");
  script_require_ports("Services/www", 80, 443);

  script_xref(name:"URL", value:"https://acme.com/software/thttpd/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");


port = get_http_port(default: 80);

banner = get_http_banner(port: port);
if ("Server: thttpd/" >!< banner)
  exit(0);

version = "unknown";

vers = eregmatch(pattern: "thttpd/([0-9a-z.]+)", string: banner);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "thttpd/installed", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:acme:thttpd:");
if (!cpe)
  cpe = 'cpe:/a:acme:thttpd';

register_product(cpe: cpe, location: "/", port: port);

log_message(data: build_detection_report(app: "thttpd", version: version, install: "/", cpe: cpe,
                                         concluded: vers[0]),
            port: port);

exit(0);
