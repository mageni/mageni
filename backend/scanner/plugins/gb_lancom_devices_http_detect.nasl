# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.143420");
  script_version("2020-01-31T09:37:51+0000");
  script_tag(name:"last_modification", value:"2020-01-31 09:37:51 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-29 07:39:45 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("LANCOM Device Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of LANCOM devices.

  This script performs HTTP based detection of LANCOM devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80, 443);
  script_mandatory_keys("LANCOM/banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

banner = get_http_banner(port: port);

if ("Server: LANCOM" >!< banner)
  exit(0);

res = http_get_cache(port: port, item: "/");

if ('"headerp">LANCOM' >< res || "LANCOM Systems Homepage" >< res) {
  set_kb_item(name: "lancom/detected", value: TRUE);
  set_kb_item(name: "lancom/http/detected", value: TRUE);
  set_kb_item(name: "lancom/http/port", value: port);
  set_kb_item(name: "lancom/http/" + port + "/detected", value: TRUE);

  version = "unknown";
  model = "unknown";

  # "headerp">LANCOM 1783VAW (over ISDN)</p>
  mod = eregmatch(pattern: '"headerp">LANCOM ([^ <]+)', string: res);
  if (isnull(mod[1])) {
    # Server: LANCOM 1721 VPN (Annex B) 7.58.0045 / 14.11.2008
    # Server: LANCOM 1821n Wireless 8.82.0169 / 20.10.2017
    # Server: LANCOM 1821+ Wireless ADSL (Ann.B) 8.00.0162 / 16.06.2010
    mod = eregmatch(pattern: 'Server: LANCOM ([^\r\n ]+)[^\r\n]+', string: res);
  }
  if (!isnull(mod[1])) {
    set_kb_item(name: "lancom/http/" + port + "/model", value: mod[1]);
    concluded = '\n    ' + mod[0];
  }

  vers = eregmatch(pattern: 'Server: LANCOM([A-Za-z0-9()/ +-]+|[A-Za-z0-9()/ +-.]+\\)) ([0-9]+\\.[0-9.]+)[^\r\n]+',
                   string: res);
  if (!isnull(vers[2])) {
    version = vers[2];
    # Avoid to report the server string twice from model and version detection
    if (!egrep(pattern: vers[2], string: concluded))
      concluded += '\n    ' + vers[0];
  }

  set_kb_item(name: "lancom/http/" + port + "/version", value: version);
  if (concluded)
    set_kb_item(name: "lancom/http/" + port + "/concluded", value: concluded);
}

exit(0);
