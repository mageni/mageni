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
  script_oid("1.3.6.1.4.1.25623.1.0.104480");
  script_version("2022-12-20T08:37:34+0000");
  script_tag(name:"last_modification", value:"2022-12-20 08:37:34 +0000 (Tue, 20 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-19 14:13:37 +0000 (Mon, 19 Dec 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-15 03:15:00 +0000 (Fri, 15 Jul 2022)");

  script_cve_id("CVE-2022-29838", "CVE-2021-33655", "CVE-2021-22898", "CVE-2021-22924", "CVE-2021-22945",
                "CVE-2021-22946", "CVE-2021-22947", "CVE-2022-22576", "CVE-2022-27775", "CVE-2022-27776",
                "CVE-2022-27781", "CVE-2022-27782", "CVE-2022-32205", "CVE-2022-32206", "CVE-2022-32207",
                "CVE-2022-32208", "CVE-2021-0561", "CVE-2022-29839");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products 5.x < 5.25.124 Multiple Vulnerabilities (WDC-22019)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist / mitigation was done:

  - CVE-2022-29838: Resolved an authentication issue with the encrypted volumes and auto mount
  feature. This bug could result in an insecure direct access to the drive information in the case
  of a device reset.

  - CVE-2021-33655: Addressed a memory out-of-bounds vulnerability that was caused while sending
  malicious data to the kernel by an ioctl cmd.

  - CVE-2021-22898, CVE-2021-22924, CVE-2021-22945, CVE-2021-22946, CVE-2021-22947, CVE-2022-22576,
  CVE-2022-27775, CVE-2022-27776, CVE-2022-27781, CVE-2022-27782, CVE-2022-32205, CVE-2022-32206,
  CVE-2022-32207, CVE-2022-32208: Updated the curl version to 7.64.0-4+deb10u3 to addressed multiple
  vulnerabilities that could allow remote attackers to obtain sensitive information, leak
  authentication or cookie header data, or facilitate a denial-of-service attack.

  - CVE-2021-0561: Updated open-source package FLAC to version 1.3.2-3+deb10u2 to resolve an
  out-of-bounds write due to missing bounds check which could lead to a local information disclosure
  with no additional execution privileges needed.

  - CVE-2022-29839: Configured the Remote Backups application to encrypt credentials to resolve an
  insufficiently protected credentials issue where if an attacker gains access to a relevant
  endpoint, they can use that information to access protected data.");

  script_tag(name:"affected", value:"Western Digital My Cloud PR2100, My Cloud PR4100, My Cloud
  EX4100, My Cloud EX2 Ultra, My Cloud Mirror Gen 2, My Cloud DL2100, My Cloud DL4100, My Cloud
  EX2100, My Cloud and WD Cloud with firmware versions prior to 5.25.124.");

  script_tag(name:"solution", value:"Update to firmware version 5.25.124 or later.");

  script_xref(name:"URL", value:"https://os5releasenotes.mycloud.com/#5.25.124");
  script_xref(name:"URL", value:"https://www.westerndigital.com/support/product-security/wdc-22019-my-cloud-firmware-version-5-25-124");

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

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.25.124")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.25.124");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
