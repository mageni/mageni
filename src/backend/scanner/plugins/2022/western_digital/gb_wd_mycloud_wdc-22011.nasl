# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.104255");
  script_version("2022-07-26T10:29:37+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:29:37 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-25 15:39:55 +0000 (Mon, 25 Jul 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-24 21:49:00 +0000 (Fri, 24 Sep 2021)");

  # nb: CVEs for DSA-5126-1 got taken from https://security-tracker.debian.org/tracker/DSA-5126-1
  script_cve_id("CVE-2020-20891", "CVE-2020-20892", "CVE-2020-20896", "CVE-2020-21688", "CVE-2020-21697",
                "CVE-2021-3566", "CVE-2022-0561", "CVE-2022-0562", "CVE-2022-0865", "CVE-2022-22999",
                "CVE-2022-29191", "CVE-2022-29192", "CVE-2022-29193", "CVE-2022-29194", "CVE-2022-29195",
                "CVE-2022-29196", "CVE-2022-29197", "CVE-2022-29198", "CVE-2022-29199", "CVE-2022-29200",
                "CVE-2022-29201", "CVE-2022-29202", "CVE-2022-29203", "CVE-2022-29204", "CVE-2022-29205",
                "CVE-2022-29206", "CVE-2022-29207", "CVE-2022-29208", "CVE-2022-29209", "CVE-2022-29210",
                "CVE-2022-29211", "CVE-2022-29212", "CVE-2022-29213", "CVE-2022-23000");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products 5.0 < 5.23.114 Multiple Vulnerabilities (WDC-22011)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist / mitigation was done:

  - Updated ffmpeg to version 7:4.1.9-0+deb10u1 to resolve DSA-5126-1 that could result in a denial
  of service vulnerability

  - Updated libtiff to version 4.4.0 to resolve CVE-2022-0561, CVE-2022-0562, CVE-2022-0865 that
  could result in a denial of service vulnerability

  - Updated TensorFlow to version 2.6.5 to resolve multiple CVEs (CVE-2022-29191 through
  CVE-2022-29213) that could result in app crashes and denial of service vulnerability

  - Updated multiple apps to resolve an issue which could result in Cross Site Scripting (XSS)
  vulnerability

  - CVE-2022-22999: An attacker with elevated privileges to access drives being backed up is able to
  construct and inject JavaScript payloads into an authenticated user's browser

  - CVE-2022-23000: Western Digital My Cloud Web App uses a weak SSLContext when attempting to
  configure port forwarding rules. This was enabled to maintain compatibility with old or outdated
  home routers. As a result, a local user with least privileges can exploit this vulnerability and
  jeopardize the integrity, confidentiality and authenticity of information transmitted. This
  vulnerability was resolved by enabling TLS ConnectionSwitching to a 'TLS' context instead of
  'SSL'.");

  script_tag(name:"affected", value:"Western Digital My Cloud PR2100, My Cloud PR4100, My Cloud
  EX4100, My Cloud EX2 Ultra, My Cloud Mirror Gen 2, My Cloud DL2100, My Cloud DL4100, My Cloud
  EX2100, My Cloud and WD Cloud with firmware versions prior to 5.23.114.");

  script_tag(name:"solution", value:"Update to firmware version 5.23.114 or later.");

  script_xref(name:"URL", value:"https://community.wd.com/t/my-cloud-os-5-firmware-release-note-v5-23-114/278556");
  script_xref(name:"URL", value:"https://os5releasenotes.mycloud.com/#5.23.114");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5126-1");
  script_xref(name:"URL", value:"https://www.westerndigital.com/support/product-security/wdc-22011-my-cloud-firmware-version-5-23-114");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:wdc:wd_cloud_firmware",
                     "cpe:/o:wdc:my_cloud_firmware",
                     "cpe:/o:wdc:my_cloud_mirror_firmware",
                     "cpe:/o:wdc:my_cloud_ex2ultra_firmware",
                     "cpe:/o:wdc:my_cloud_ex2100_firmware",
                     "cpe:/o:wdc:my_cloud_ex4100_firmware",
                     "cpe:/o:wdc:my_cloud_dl2100_firmware",
                     "cpe:/o:wdc:my_cloud_dl4100_firmware",
                     "cpe:/o:wdc:my_cloud_pr2100_firmware",
                     "cpe:/o:wdc:my_cloud_pr4100_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+")) # nb: The HTTP Detection is only able to extract the major release like 2.30
  exit(0);

version = infos["version"];

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.23.114")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.23.114");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
