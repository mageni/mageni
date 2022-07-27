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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141999");
  script_version("$Revision: 13704 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 20:06:21 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-15 09:13:25 +0700 (Fri, 15 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Snom Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Snom devices.

  The script sends a HTTP connection request to the server and attempts to detect Snom devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/");
if (res !~ "^HTTP/1\.[01] 401" && res !~ "<TITLE>snom ?D?[0-9]+" && "WWW-Authenticate: Basic realm" >!< res && "Server: snom embedded" >!< res)
  exit(0);

# e.g.:
# <TITLE>snom D715</TITLE>
# <TITLE>snom 300</TITLE>
# <TITLE>snom 320</TITLE>
# <TITLE>snomD305-8325FE</TITLE>
# nb: Seems the name on the devices can be changed so we're not always detecting the model from the title.
# nb: Some devices are also reporting a 403 forbidden with an <TITLE>snom VoIP phone: Error</TITLE> error.
mod = eregmatch(pattern: "<TITLE>snom ?(D?[0-9]+)", string: res);
if (isnull(mod[1])) {
  # After a couple of tries we get an error message with the model
  for (i=0; i<5; i++) {
    req = http_get(port: port, item: "/");
    res = http_keepalive_send_recv(port: port, data: req);
    mod = eregmatch(pattern: "<TITLE>snom ?(D?[0-9]+)", string: res);
    if (!isnull(mod[1]))
      break;
  }
  if ("Server: snom embedded" >!< res && "<TITLE>snom" >!< res && 'Basic realm="snom' >!< res)
    exit(0);
}

set_kb_item(name: "snom/detected", value: TRUE);
set_kb_item(name: "snom/http/port", value: port);
if (!isnull(mod[1]))
  set_kb_item(name: "snom/http/" + port + "/model", value: mod[1]);

exit(0);