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

CPE = "cpe:/a:openwrt:openwrt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148627");
  script_version("2022-08-23T10:11:31+0000");
  script_tag(name:"last_modification", value:"2022-08-23 10:11:31 +0000 (Tue, 23 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-23 07:03:06 +0000 (Tue, 23 Aug 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-25 16:15:00 +0000 (Wed, 25 Mar 2020)");

  script_cve_id("CVE-2020-7248", "CVE-2020-7982");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenWRT < 18.06.7, 19.x < 19.07.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openwrt_ssh_login_detect.nasl");
  script_mandatory_keys("openwrt/detected");

  script_tag(name:"summary", value:"OpenWRT is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-7248: libubox tagged binary data JSON serialization

  - CVE-2020-7982: Opkg susceptible to MITM");

  script_tag(name:"affected", value:"OpenWRT version 18.06.6 and prior and version 19.07.0.");

  script_tag(name:"solution", value:"Update to version 18.06.7, 19.07.1 or later.");

  script_xref(name:"URL", value:"https://openwrt.org/advisory/2020-01-31-1");
  script_xref(name:"URL", value:"https://openwrt.org/advisory/2020-01-31-2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "18.06.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.06.7");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "19.07.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.07.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
