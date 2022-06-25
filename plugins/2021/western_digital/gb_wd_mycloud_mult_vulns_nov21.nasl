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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117762");
  script_version("2021-11-09T03:03:35+0000");
  script_tag(name:"last_modification", value:"2021-11-09 03:03:35 +0000 (Tue, 09 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-08 13:34:38 +0000 (Mon, 08 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-30 15:20:00 +0000 (Thu, 30 Sep 2021)");

  script_cve_id("CVE-2021-34798", "CVE-2021-36160", "CVE-2021-39275", "CVE-2021-40438", "CVE-2020-20445",
                "CVE-2020-20446", "CVE-2020-20453", "CVE-2020-21041", "CVE-2020-22015", "CVE-2020-22016",
                "CVE-2020-22017", "CVE-2020-22019", "CVE-2020-22020", "CVE-2020-22021", "CVE-2020-22022",
                "CVE-2020-22023", "CVE-2020-22025", "CVE-2020-22026", "CVE-2020-22027", "CVE-2020-22028",
                "CVE-2020-22029", "CVE-2020-22030", "CVE-2020-22031", "CVE-2020-22032", "CVE-2020-22033",
                "CVE-2020-22034", "CVE-2020-22035", "CVE-2020-22036", "CVE-2020-22037", "CVE-2020-22049",
                "CVE-2020-22054", "CVE-2020-35965", "CVE-2021-38114", "CVE-2021-38171", "CVE-2021-38291");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products 5.0 < 5.18.117 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2021-34798, CVE-2021-36160, CVE-2021-39275,
  CVE-2021-40438:

  Addressed multiple Apache HTTP Server vulnerabilities by updating the version to 2.4.38-3+deb10u6

  - CVE-2020-20445, CVE-2020-20446, CVE-2020-20453, CVE-2020-21041, CVE-2020-22015, CVE-2020-22016,
  CVE-2020-22017, CVE-2020-22019, CVE-2020-22020, CVE-2020-22021, CVE-2020-22022, CVE-2020-22023,
  CVE-2020-22025, CVE-2020-22026, CVE-2020-22027, CVE-2020-22028, CVE-2020-22029, CVE-2020-22030,
  CVE-2020-22031, CVE-2020-22032, CVE-2020-22033, CVE-2020-22034, CVE-2020-22035, CVE-2020-22036,
  CVE-2020-22037, CVE-2020-22049, CVE-2020-22054, CVE-2020-35965, CVE-2021-38114, CVE-2021-38171,
  CVE-2021-38291:

  Addressed multiple FFmpeg vulnerabilities by updating the version to 7:4.1.8-0+deb10u1");

  script_tag(name:"affected", value:"Western Digital My Cloud PR2100, My Cloud PR4100, My Cloud EX2
  Ultra, My Cloud EX2100, My Cloud EX4100, My Cloud Mirror Gen 2, My Cloud DL2100, My Cloud DL4100,
  My Cloud (P/N: WDBCTLxxxxxx-10) and WD Cloud (Japan) with firmware versions prior to 5.18.117.");

  script_tag(name:"solution", value:"Update to firmware version 5.18.117 or later.");

  script_xref(name:"URL", value:"https://community.wd.com/t/my-cloud-os-5-firmware-release-note-v5-18-117/272195");
  script_xref(name:"URL", value:"https://www.westerndigital.com/support/product-security/wdc-21012-my-cloud-os5-firmware-version-5-18-117");

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

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.17.107")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.18.117");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);