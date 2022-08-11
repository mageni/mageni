###############################################################################
# OpenVAS Vulnerability Test
#
# Dell SonicWall EMail Security Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103929");
  script_version("2020-01-08T16:29:50+0000");
  script_tag(name:"last_modification", value:"2020-01-08 16:29:50 +0000 (Wed, 08 Jan 2020)");
  script_tag(name:"creation_date", value:"2014-03-28 12:48:51 +0100 (Fri, 28 Mar 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SonicWall Email Security Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of SonicWall Email Security.

  The script performs a HTTP based detection of SonicWall Email Security.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

url = "/login.html";
res = http_get_cache(port: port, item: url);

if ("<title>Login</title>" >< res && ">Email Security" >< res && res =~ "(SonicWall|Dell)") {
  set_kb_item(name: "sonicwall/email_security/detected", value: TRUE);
  set_kb_item(name: "sonicwall/email_security/http/port", value: port);
  set_kb_item(name: "sonicwall/email_security/http/" + port + "/concluded_url", value: report_vuln_url(port: port, url: url, url_only: TRUE));

  version = "unknown";

  # id="firmwareVersion" value="9.0.3.1635">
  vers = eregmatch(pattern: 'id="firmwareVersion" value="([0-9.]+)"', string: res);
  if (isnull(vers[1])) {
    # class="lefthand">9.0.3.1635<
    vers = eregmatch(pattern: 'class="lefthand">([0-9.]+)<', string: res);
  }

  if (!isnull(vers[1])) {
    version = vers[1];
    concluded = '\n  ' + vers[0];
  }

  set_kb_item(name: "sonicwall/email_security/http/" + port + "/version", value: version);

  # id="modelNumber" value="3300">
  # id="modelNumber" value="VMWare">
  # id="modelNumber" value="">
  mod  = eregmatch(pattern: 'id="modelNumber" value="([^"]+)"', string: res);
  if (!isnull(mod[1]) && mod[1] != "") {
    set_kb_item(name: "sonicwall/email_security/http/" + port + "/model", value: mod[1]);
    concluded += '\n  ' + mod[0];
  }

  if (concluded)
    set_kb_item(name: "sonicwall/email_security/http/" + port + "/concluded", value: concluded);
}

exit(0);
