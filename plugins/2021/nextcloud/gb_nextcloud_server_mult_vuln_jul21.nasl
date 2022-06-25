# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:nextcloud:nextcloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146310");
  script_version("2021-07-16T06:42:50+0000");
  script_tag(name:"last_modification", value:"2021-07-16 10:17:24 +0000 (Fri, 16 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-16 06:23:52 +0000 (Fri, 16 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2021-32678", "CVE-2021-32679", "CVE-2021-32680", "CVE-2021-32688", "CVE-2021-32703",
                "CVE-2021-32705", "CVE-2021-32725", "CVE-2021-32726", "CVE-2021-32733", "CVE-2021-32734",
                "CVE-2021-32741");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server Multiple Vulnerabilities (Jul 2021)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl");
  script_mandatory_keys("nextcloud/installed");

  script_tag(name:"summary", value:"Nextcloud Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-32678: Ratelimit not applied on OCS API responses

  - CVE-2021-32679: Filenames not escaped by default in controllers using DownloadResponse

  - CVE-2021-32680: Audit log is not properly logging unsetting of share expiration date

  - CVE-2021-32688: Application specific tokens can change their own scope

  - CVE-2021-32703: Lack of ratelimit on shareinfo endpoint

  - CVE-2021-32705: Lack of ratelimit on public DAV endpoint

  - CVE-2021-32725: Default share permissions not respected for federated reshares

  - CVE-2021-32726: Webauthn tokens not removed after user has been deleted

  - CVE-2021-32733: XSS in Nextcloud Text application

  - CVE-2021-32734: File path disclosure of shared files in Nextcloud Text application

  - CVE-2021-32741: Lack of ratelimit on public share link mount endpoint");

  script_tag(name:"affected", value:"Nextcloud server 19.0.12 and prior, 20.0.x through 20.0.10 and
  21.0.x through 21.0.2.");

  script_tag(name:"solution", value:"Update to version 19.0.13, 20.0.11, 21.0.3 or later.");

  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-48rx-3gmf-g74j");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-3hjp-26x8-mhf6");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-fxpq-wq7c-vppf");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-48m7-7r2r-838r");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-375p-cxxq-gc9p");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-fjv7-283f-5m54");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-6f6v-h9x9-jj4v");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-6qr9-c846-j8mg");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-x4w3-jhcr-57pq");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-6hf5-c2c4-2526");
  script_xref(name:"URL", value:"https://github.com/nextcloud/security-advisories/security/advisories/GHSA-crvj-vmf7-xrvr");

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

if (version_is_less(version: version, test_version: "19.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.0.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "20.0.0", test_version2: "20.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.0.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "21.0.0", test_version2: "21.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "21.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
