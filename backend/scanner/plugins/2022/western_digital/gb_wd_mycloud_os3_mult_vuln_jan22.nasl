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
  script_oid("1.3.6.1.4.1.25623.1.0.117917");
  script_version("2022-01-21T11:25:35+0000");
  script_tag(name:"last_modification", value:"2022-01-24 11:12:31 +0000 (Mon, 24 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-21 11:14:16 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-27 19:09:00 +0000 (Mon, 27 Sep 2021)");

  script_cve_id("CVE-2021-34798", "CVE-2021-36160", "CVE-2021-39275", "CVE-2021-40438");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products < 2.12.144 Multiple Vulnerabilities (WDC-22001)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone to multiple
  vulnerabilities in the Apache HTTP Server.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-34798: NULL pointer dereference in httpd core

  - CVE-2021-36160: mod_proxy_uwsgi out of bound read

  - CVE-2021-39275: ap_escape_quotes buffer overflow

  - CVE-2021-40438: mod_proxy SSRF");

  script_tag(name:"affected", value:"Western Digital My Cloud EX2, My Cloud EX4 and My Cloud Mirror
  with firmware versions prior to 2.12.144.");

  script_tag(name:"solution", value:"Update to firmware version 2.12.144 or later.");

  script_xref(name:"URL", value:"https://www.westerndigital.com/support/product-security/wdc-22001-my-cloud-os3-firmware-2-12-144");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:wdc:my_cloud_mirror_firmware",
                     "cpe:/o:wdc:my_cloud_ex2_firmware",
                     "cpe:/o:wdc:my_cloud_ex4_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+")) # nb: The HTTP Detection is only able to extract the major release like 2.30
  exit(0);

version = infos["version"];

if (version_is_less(version: version, test_version: "2.12.144")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.12.144");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
