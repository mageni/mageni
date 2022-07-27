# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143103");
  script_version("2019-11-08T02:45:39+0000");
  script_tag(name:"last_modification", value:"2019-11-08 02:45:39 +0000 (Fri, 08 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-07 09:52:07 +0000 (Thu, 07 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("LIVE555 Streaming Media Server Detection (HTTP)");

  script_tag(name:"summary", value:"This script performs a HTTP based detection of LIVE555 Streaming Media Server.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

port = get_http_port(default: 80);

banner = get_http_banner(port: port);

if (!banner || "LIVE555 Streaming Media" >!< banner)
  exit(0);

set_kb_item(name: "live555/streaming_media/detected", value: TRUE);
set_kb_item(name: "live555/streaming_media/http/port", value: port);

version = "unknown";

# Server: LIVE555 Streaming Media v2017.10.28
vers = eregmatch(pattern: "LIVE555 Streaming Media v([0-9.]+)", string: banner);
if (!isnull(vers[1])) {
  version = vers[1];
  set_kb_item(name: "live555/streaming_media/http/" + port + "/concluded", value: vers[0]);
}

set_kb_item(name: "live555/streaming_media/http/" + port + "/version", value: version);

exit(0);
