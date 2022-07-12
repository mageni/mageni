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

CPE = "cpe:/o:huawei:usg9500_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145669");
  script_version("2021-03-29T07:18:00+0000");
  script_tag(name:"last_modification", value:"2021-03-30 10:22:27 +0000 (Tue, 30 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-29 07:12:11 +0000 (Mon, 29 Mar 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2020-9212");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Improper Information Processing Vulnerability in Huawei Products (huawei-sa-20210203-01-informationleak)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a vulnerability that the device improperly handles the
  information when a user logs in to device.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The attacker can exploit the vulnerability to performs some operation can
  get information and cause information leak.");

  script_tag(name:"impact", value:"The attacker can exploit the vulnerability to performs some operation can
  get information and cause information leak.");

  script_tag(name:"affected", value:"USG9500 versions V500R005C00SPC100 V500R005C00SPC200 V500R005C20SPC300 V500R005C20SPC500 V500R005C20SPC600.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20210203-01-informationleak-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

patch = get_kb_item("huawei/vrp/patch");

if (version =~ "^V500R005C00SPC100" || version =~ "^V500R005C00SPC200" || version =~ "^V500R005C20SPC300" ||
    version =~ "^V500R005C20SPC500" || version =~ "^V500R005C20SPC600") {
  report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V500R005C20SPH302");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
