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

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143081");
  script_version("2019-11-05T09:17:26+0000");
  script_tag(name:"last_modification", value:"2019-11-05 09:17:26 +0000 (Tue, 05 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-10-30 08:59:37 +0000 (Wed, 30 Oct 2019)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:P");

  script_cve_id("CVE-2019-3976", "CVE-2019-3977", "CVE-2019-3978", "CVE-2019-3979");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS < 6.44.6 (LTS), < 6.45.7 (Stable) Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MikroTik RouterOS is prone to multiple vulnerabilities:

  - Relative Path Traversal in NPK Parsing (CVE-2019-3976)

  - Insufficient Validation of Upgrade Package's Origin (CVE-2019-3977)

  - Insufficient Protections of a Critical Resource (DNS Requests/Cache) (CVE-2019-3978)

  - Improper DNS Response Handling (CVE-2019-3979)");

  script_tag(name:"affected", value:"MikroTik RouterOS prior to version 6.44.6 (LTS) and 6.45.7 (Stable).");

  script_tag(name:"solution", value:"Update to version 6.44.6 (LTS), 6.45.7 (Stable) or later.");

  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs/stable-release-tree");
  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs/long-term-release-tree");
  script_xref(name:"URL", value:"https://www.tenable.com/security/research/tra-2019-46");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.44.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.44.6");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^6\.45") {
  if (version_is_less(version: version, test_version: "6.45.7")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.45.7");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
