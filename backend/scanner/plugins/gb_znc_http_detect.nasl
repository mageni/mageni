# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144110");
  script_version("2020-06-16T13:13:04+0000");
  script_tag(name:"last_modification", value:"2020-06-17 08:59:13 +0000 (Wed, 17 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-16 02:30:35 +0000 (Tue, 16 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ZNC Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of ZNC.

  HTTP based detection of ZNC.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 6667);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = http_get_port(default: 6667);

res = http_get_cache(port: port, item: "/");

if (concl = eregmatch(string: res, pattern: '(Server\\s*:\\s*ZNC|ZNC - Web Frontend)[^\r\n]+', icase: TRUE)) {
  version = "unknown";
  concluded = chomp(concl[0]);

  set_kb_item(name: "znc/detected", value: TRUE);
  set_kb_item(name: "znc/http/port", value: port);

  # nb: Note that the version itself can be hidden via a setting of ZNC.
  #
  # Server: ZNC - http://znc.in
  # Server: ZNC 1.7.5 - https://znc.in
  # Server: ZNC 1.9.x-git-9-84d8375a - https://znc.in
  # Server: ZNC 1.7.0+deb0+trusty1 - https://znc.in
  # Server: ZNC - 1.6.0 - http://znc.in
  vers = eregmatch(pattern: "aServer\s*:\s*ZNC( \-)? ([0-9.]+)([^ ]+)? - http", string: res);
  if (!isnull(vers[2])) {
    version = vers[2];
    concluded = vers[0];
  }

  # or if the server banner is hidden behind e.g. a Proxy the related HTML code for the version:
  #
  # <div id="tag"><p>ZNC - 1.6.0 - <a href="http://znc.in">http://znc.in</a></p></div>
  # <div id="banner"><p>ZNC 1.7.5 - <a href="https://znc.in">https://znc.in</a></p></div>
  if (version == "unknown") {
    vers = eregmatch(pattern: ">ZNC( \-)? ([0-9.]+) - <", string: res);
    if (!isnull(vers[2])) {
      version = vers[2];
      concluded = vers[0];
    }
  }

  set_kb_item(name: "znc/http/" + port + "/concluded", value: concluded);
  set_kb_item(name: "znc/http/" + port + "/version", value: version);
}

exit(0);
