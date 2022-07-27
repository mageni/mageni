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
  script_oid("1.3.6.1.4.1.25623.1.0.146167");
  script_version("2021-06-23T06:22:30+0000");
  script_tag(name:"last_modification", value:"2021-06-23 10:20:01 +0000 (Wed, 23 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-23 06:10:34 +0000 (Wed, 23 Jun 2021)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:N/I:N/A:C");

  script_cve_id("CVE-2021-22342");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Information Leak Vulnerability in Huawei Products (huawei-sa-20210428-01-infomationleak)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is an information leak vulnerability in Huawei products.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A module does not deal with specific input sufficiently. High
  privilege attackers can exploit this vulnerability by performing some operations. This can lead
  to information leak.");

  script_tag(name:"affected", value:"IPS Module versions V500R005C00 V500R005C10 V500R005C20

  NGFW Module versions V500R005C00 V500R005C10 V500R005C20

  SeMG9811 versions V500R005C00

  USG9500 versions V500R001C00 V500R001C20 V500R001C30 V500R001C50 V500R001C60 V500R001C80 V500R005C00
  V500R005C10 V500R005C20");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20210428-01-infomationleak-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

version = toupper(version);
patch = get_kb_item("huawei/vrp/patch");

if (version =~ "^V500R001C00" || version =~ "^V500R001C20" || version =~ "^V500R001C30" ||
    version =~ "^V500R001C50" || version =~ "^V500R001C60" || version =~ "^V500R001C80" ||
    version =~ "^V500R005C00" || version =~ "^V500R005C10" || version =~ "^V500R005C20") {
  if (version_is_less(version: version, test_version: "V500R005C20SPC500")) {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V500R005C20SPC500", fixed_patch: "V500R005SPH008");
    security_message(port: 0, data: report);
    exit(0);
  } else {
    if (!patch || version_is_less(version: version, test_version: "V500R005SPH008")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch,
                                fixed_version: "V500R005C20SPC500", fixed_patch: "V500R005SPH008");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);
