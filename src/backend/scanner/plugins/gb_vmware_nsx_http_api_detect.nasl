# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105420");
  script_version("2022-02-24T09:21:45+0000");
  script_tag(name:"last_modification", value:"2022-02-24 09:21:45 +0000 (Thu, 24 Feb 2022)");
  script_tag(name:"creation_date", value:"2015-10-27 13:50:19 +0100 (Tue, 27 Oct 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Vmware NSX Detection (HTTP-API)");

  script_tag(name:"summary", value:"HTTP-API based detection of Vmware NSX.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_vmware_nsx_http_detect.nasl");
  script_mandatory_keys("vmware/nsx/http/detected");

  script_add_preference(name:"NSX API Username: ", value:"", type:"entry", id:1);
  script_add_preference(name:"NSX API Password: ", type:"password", value:"", id:2);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_kb_item("vmware/nsx/http/port"))
  exit(0);

user = script_get_preference("NSX API Username: ", id:1);
pass = script_get_preference("NSX API Password: ", id:2);

version = "unknown";
build = "unknown";

if (!user || !pass)
  exit(0);

url = "/api/1.0/appliance-management/global/info";

userpass = user + ":" + pass;
userpass64 = base64(str: userpass);

headers = make_array("Authorization", "Basic " + userpass64);

req = http_get_req(port: port, url: url, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if (res !~ '^\\{"currentLoggedInUser"')
  exit(0);

# {"currentLoggedInUser":"admin","versionInfo":{"majorVersion":"6","minorVersion":"4","patchVersion":"13","buildNumber":"19307994"},"readOnlyAccess":false}
major = eregmatch(pattern: '"majorVersion":"([^"]+)"', string: res);
minor = eregmatch(pattern: '"minorVersion":"([^"]+)"', string: res);
patch = eregmatch(pattern: '"patchVersion":"([^"]+)"', string: res);
bld   = eregmatch(pattern: '"buildNumber":"([^"]+)"', string: res);

if (!isnull(major[1]) && !isnull(minor[1])) {
  version = major[1] + "." + minor[1];
  set_kb_item(name: "vmware/nsx/http-api/" + port + "/concluded", value: res);
}

if (!isnull(patch[1]))
  version += "." + patch[1];

if (!isnull(bld[1]))
  build = bld[1];

set_kb_item(name: "vmware/nsx/http-api/detected", value: TRUE);
set_kb_item(name: "vmware/nsx/http-api/port", value: port);

set_kb_item(name: "vmware/nsx/http-api/" + port + "/version", value: version);
set_kb_item(name: "vmware/nsx/http-api/" + port + "/build", value: build);

exit(0);
