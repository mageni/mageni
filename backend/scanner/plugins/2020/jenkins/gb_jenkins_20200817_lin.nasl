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

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112811");
  script_version("2020-08-18T13:31:35+0000");
  script_tag(name:"last_modification", value:"2020-08-19 10:25:31 +0000 (Wed, 19 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-18 13:26:11 +0000 (Tue, 18 Aug 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-17638");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jenkins < 2.243, < 2.235.5 LTS Buffer corruption in bundled Jetty (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Jenkins is prone to a buffer corruption in bundled Jetty.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In Eclipse Jetty in case of too large response headers,
  Jetty throws an exception to produce an HTTP 431 error. When this happens, the ByteBuffer
  containing the HTTP response headers is released back to the ByteBufferPool twice. Because of
  this double release, two threads can acquire the same ByteBuffer from the pool and while thread1
  is about to use the ByteBuffer to write response1 data, thread2 fills the ByteBuffer with response2 data.
  Thread1 then proceeds to write the buffer that now contains response2 data.

  This results in client1, which issued request1 and expects responses,
  to see response2 which could contain sensitive data belonging to client2
  (HTTP session ids, authentication credentials, etc.).");

  script_tag(name:"impact", value:"This vulnerability may allow unauthenticated attackers
  to obtain HTTP response headers that may include sensitive data intended for another user.");

  script_tag(name:"affected", value:"Jenkins version 2.242 and prior and 2.235.4 LTS and prior.");

  script_tag(name:"solution", value:"Update to version 2.243, 2.235.5 LTS or later.");

  script_xref(name:"URL", value:"https://www.jenkins.io/security/advisory/2020-08-17/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_full(cpe: CPE, port: port))
  exit(0);

if(!version = infos["version"])
  exit(0);

location = infos["location"];
proto = infos["proto"];

if(get_kb_item("jenkins/" + port + "/is_lts")) {
  if(version_is_less(version: version, test_version: "2.235.5")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.235.5", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if(version_is_less(version: version, test_version: "2.243")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.243", install_path: location);
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
