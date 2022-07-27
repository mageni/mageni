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
  script_oid("1.3.6.1.4.1.25623.1.0.145191");
  script_version("2021-01-19T02:29:41+0000");
  script_tag(name:"last_modification", value:"2021-01-22 11:28:48 +0000 (Fri, 22 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-19 01:55:28 +0000 (Tue, 19 Jan 2021)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-9127");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Command Injection Vulnerability in Some Huawei Products (huawei-sa-20201111-02-injection)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Some Huawei products have a command injection vulnerability.");

  script_tag(name:"insight", value:"Due to insufficient input validation, an attacker with high privilege may
  inject some malicious codes in some files of the affected products. Successful exploit may cause command
  injection.");

  script_tag(name:"impact", value:"An attacker may exploit the vulnerability to cause command injection.");

  script_tag(name:"affected", value:"NIP6300 versions V500R001C30 V500R001C60

  NIP6600 versions V500R001C30 V500R001C60

  Secospace USG6300 versions V500R001C30 V500R001C60

  Secospace USG6500 versions V500R001C30 V500R001C60

  Secospace USG6600 versions V500R001C30 V500R001C60

  USG9500 versions V500R001C30 V500R001C60");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20201111-02-injection-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:usg6300_firmware",
                     "cpe:/o:huawei:usg6500_firmware",
                     "cpe:/o:huawei:usg6600_firmware",
                     "cpe:/o:huawei:usg9500_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

version = toupper(infos["version"]);

if (version =~ "^V500R001C30" || version =~ "^V500R001C60") {
  report = report_fixed_ver(installed_version: version, fixed_version: "V500R005C00SPC200");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
