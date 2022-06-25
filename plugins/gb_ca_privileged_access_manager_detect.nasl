###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ca_privileged_access_manager_detect.nasl 10890 2018-08-10 12:30:06Z cfischer $
#
# CA Privileged Access Manager Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141190");
  script_version("$Revision: 10890 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:30:06 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-06-19 10:04:45 +0700 (Tue, 19 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("CA Privileged Access Manager Detection");

  script_tag(name:"summary", value:"Detection of CA Privileged Access Manager.

The script sends a connection request to the server and attempts to detect CA Privileged Access Manager and to
extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.ca.com/us/products/ca-privileged-access-manager.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

res = http_get_cache(port: port, item: "/");

if ("<title>CA Privileged Access Manager</title>" >< res && "ACCESSKEY=" >< res) {
  version = "unknown";

  vers = eregmatch(pattern: 'id="xsuiteVersion" value="([0-9.]+)', string: res);
  if (!isnull(vers[1]))
    version = vers[1];
  else {
    vers = eregmatch(pattern: "CAPAMClientInstall_V([0-9.]+)\.", string: res);
    if (!isnull(vers[1]))
      version = vers[1];
  }

  set_kb_item(name: "ca_priv_access_manager/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:ca:privileged_access_manager:");
  if (!cpe)
    cpe = 'cpe:/a:ca:privileged_access_manager';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "CA Privileged Access Manager", version: version, install: "/",
                                           cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
