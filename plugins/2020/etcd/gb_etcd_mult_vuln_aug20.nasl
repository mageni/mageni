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

CPE = "cpe:/a:etcd:etcd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144378");
  script_version("2020-08-10T06:40:06+0000");
  script_tag(name:"last_modification", value:"2020-08-11 10:23:00 +0000 (Tue, 11 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-10 06:18:11 +0000 (Mon, 10 Aug 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2020-15106", "CVE-2020-15112", "CVE-2020-15113", "CVE-2020-15114", "CVE-2020-15115",
                "CVE-2020-15136");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("etcd < 3.3.23, 3.4.x < 3.4.10 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_etcd_detect.nasl");
  script_mandatory_keys("etcd/installed");

  script_tag(name:"summary", value:"etcd is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - A large slice causes panic in decodeRecord method (CVE-2020-15106)

  - An entry with large index causes panic in WAL ReadAll method (CVE-2020-15112)

  - Directories created via os.MkdirAll are not checked for permissions (CVE-2020-15113)

  - Gateway can include itself as an endpoint resulting in resource exhaustion (CVE-2020-15114)

  - No minimum password length (CVE-2020-15115)

  - Gateway TLS authentication only applies to endpoints detected in DNS SRV records (CVE-2020-15136)");

  script_tag(name:"affected", value:"etcd prior to version 3.3.23 and 3.4.x prior to 3.4.10.");

  script_tag(name:"solution", value:"Update to version 3.3.23, 3.4.10 or later.");

  script_xref(name:"URL", value:"https://github.com/etcd-io/etcd/security/advisories/GHSA-p4g4-wgrh-qrg2");
  script_xref(name:"URL", value:"https://github.com/etcd-io/etcd/security/advisories/GHSA-m332-53r6-2w93");
  script_xref(name:"URL", value:"https://github.com/etcd-io/etcd/security/advisories/GHSA-chh6-ppwq-jh92");
  script_xref(name:"URL", value:"https://github.com/etcd-io/etcd/security/advisories/GHSA-2xhq-gv6c-p224");
  script_xref(name:"URL", value:"https://github.com/etcd-io/etcd/security/advisories/GHSA-4993-m7g5-r9hh");
  script_xref(name:"URL", value:"https://github.com/etcd-io/etcd/security/advisories/GHSA-wr2v-9rpq-c35q");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.3.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.4", test_version2: "3.4.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.4.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
