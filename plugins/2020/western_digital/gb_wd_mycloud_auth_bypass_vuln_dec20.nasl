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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145065");
  script_version("2020-12-17T10:29:45+0000");
  script_tag(name:"last_modification", value:"2020-12-17 11:08:11 +0000 (Thu, 17 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-17 09:15:31 +0000 (Thu, 17 Dec 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-29563");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products 5.0 < 5.07.118 Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone to an authentication
  bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a NAS Admin authentication bypass vulnerability that could allow an
  unauthenticated user to gain access to the device.

  The specific flaw exists within the mod_rewrite module. The issue results from the way the software parses URLs
  to make authorization decisions.");

  script_tag(name:"impact", value:"An attacker can leverage this vulnerability to bypass authentication on the system.");

  script_tag(name:"affected", value:"Western Digital My Cloud PR2100, PR4100, EX2 Ultra, EX4100 and Mirror Gen 2
  with firmware versions prior to 5.07.118.");

  script_tag(name:"solution", value:"Update to firmware version 5.07.118 or later.");

  script_xref(name:"URL", value:"https://www.westerndigital.com/support/productsecurity/wdc-20010-my-cloud-os5-firmware-5-07-118");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-20-1446/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:wdc:my_cloud_mirror_firmware",
                     "cpe:/o:wdc:my_cloud_ex2ultra_firmware",
                     "cpe:/o:wdc:my_cloud_ex4100_firmware",
                     "cpe:/o:wdc:my_cloud_pr2100_firmware",
                     "cpe:/o:wdc:my_cloud_pr4100_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+")) # nb: The HTTP Detection is only able to extract the major release like 2.30
  exit(0);

version = infos["version"];

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.07.117")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.07.118");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
