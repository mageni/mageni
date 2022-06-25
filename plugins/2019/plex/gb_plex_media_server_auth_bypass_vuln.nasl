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

CPE = "cpe:/a:plex:plex_media_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143159");
  script_version("2019-11-21T07:47:15+0000");
  script_tag(name:"last_modification", value:"2019-11-21 07:47:15 +0000 (Thu, 21 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-21 05:10:49 +0000 (Thu, 21 Nov 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2018-21031");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Plex Media Server Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_plex_media_server_remote_detect.nasl", "gb_tautulli_detect.nasl");
  script_mandatory_keys("plex_media_server/detected", "tautulli/plex_token");

  script_tag(name:"summary", value:"Plex Media Server allows remote attackers to bypass intended access control
  because X-Plex-Token is mishandled, and can be retrieved from Tautulli if no authentication is enabled there.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An unauthenticated attacker might download various content from the Plex server.");

  script_tag(name:"solution", value:"As a workaround enable authentication for Tautulli to prevent an
  unauthenticated attacker to obtain the token.");

  script_xref(name:"URL", value:"https://www.elladodelmal.com/2018/08/shodan-es-de-cine-hacking-tautulli-un.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

if (!token = get_kb_item("tautulli/plex_token"))
  exit(99);

url = dir + "/?X-Plex-Token=" + token;

if (http_vuln_check(port: port, url: url, pattern: "<MediaContainer", check_header: TRUE)) {
  report = 'It was possible to access Plex at ' + report_vuln_url(port: port, url: url, url_only: TRUE) +
           ' with the obtained token "' + token + '" from Tautulli.';
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
