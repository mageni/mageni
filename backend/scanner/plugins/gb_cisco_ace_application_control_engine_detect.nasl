###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ace_application_control_engine_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco ACE Application Control Engine Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106257");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-16 15:00:47 +0700 (Fri, 16 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco ACE Application Control Engine Detection");

  script_tag(name:"summary", value:"Detection of Cisco ACE Application Control Engine

The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

res = http_get_cache(port: port, item: "/");

if ('cuesLoginProductName">ACE 4710 Device Manager' >< res) {
  version = "unknown";

  cpe = 'cpe:/h:cisco:ace_4710';

  vers = eregmatch(pattern: 'cuesLoginVersionInfo">Version ([^<]+)</div>', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "cisco_ace/version", value: version);
    cpe = cpe + ":" + tolower(version);
  }

  set_kb_item(name: "cisco_ace/detected", value: TRUE);

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Cisco ACE 4710 Application Control Engine",
                                           version: version, install: "/", cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
