###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wpjobboard_detect.nasl 10913 2018-08-10 15:35:20Z cfischer $
#
#  WPJobBoard Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.107234");
  script_version("$Revision: 10913 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:35:20 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-09-05 16:22:38 +0700 (Tue, 05 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WPJobBoard Detection");

  script_tag(name:"summary", value:"Detection of WPJobBoard.

The script sends a connection request to the server and attempts to detect WPJobBoard and to
extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");

  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://wpjobboard.net/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/");

if ('target="_blank">WPJobBoard</a></p>' >< res || 'wp-content/plugins/wpjobboard/public/' >< res) {

  version = "unknown";
  ver = eregmatch(pattern: "wpjobboard/public/js/frontend.js\?ver=([0-9.]+)'></script>", string: res);

  if (!isnull(ver[1])) {
    version = ver[1];
    set_kb_item(name: "wpjobboard/version", value: version);
  }

  set_kb_item(name: "wpjobboard/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:wpjobboard:wpjobboard:");
  if (!cpe)
    cpe = 'cpe:/a:wpjobboard:wpjobboard';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "WPJobBoard", version: version, install: "/",
                                           cpe: cpe, concluded: ver[0]),
              port: port);
}

exit(0);
