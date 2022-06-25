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

CPE = 'cpe:/a:isc:bind';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142322");
  script_version("2019-05-17T11:35:17+0000");
  script_tag(name:"last_modification", value:"2019-05-17 11:35:17 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2019-04-30 06:46:52 +0000 (Tue, 30 Apr 2019)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2019-6467");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ISC BIND DoS Vulnerability - CVE-2019-6467 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("bind_version.nasl", "os_detection.nasl");
  script_mandatory_keys("ISC BIND/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"ISC BIND is prone to a denial of service vulnerability due to an assertion
  failure in query.c");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A programming error in the nxdomain-redirect feature can cause an assertion
  failure in query.c if the alternate namespace used by nxdomain-redirect is a descendant of a zone that is served
  locally.

  The most likely scenario where this might occur is if the server, in addition to performing NXDOMAIN redirection
  for recursive clients, is also serving a local copy of the root zone or using mirroring to provide the root zone,
  although other configurations are also possible.");

  script_tag(name:"impact", value:"An attacker who can deliberately trigger the condition on a server with a
  vulnerable configuration can cause BIND to exit, denying service to other clients.");

  script_tag(name:"affected", value:"BIND 9.12.0 to 9.12.4 and 9.14.0. Also affects all releases in the 9.13
  development branch.");

  script_tag(name:"solution", value:"Update to version 9.12.4-P1, 9.14.1 or later.");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2019-6467");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_proto(cpe: CPE, port: port, exit_no_version: TRUE)) exit(0);
version = infos["version"];
proto = infos["proto"];

if (version !~ "^9\.")
  exit(99);

if (version_in_range(version: version, test_version: "9.12.0", test_version2: "9.12.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.12.4-P1");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.13.0", test_version2: "9.14.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.14.1");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
