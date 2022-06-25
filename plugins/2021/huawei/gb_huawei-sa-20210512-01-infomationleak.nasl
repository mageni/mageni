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
  script_oid("1.3.6.1.4.1.25623.1.0.147211");
  script_version("2021-11-24T04:37:32+0000");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-24 04:12:50 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2021-22356");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Weak Secure Algorithm Vulnerability in Huawei Product (huawei-sa-20210512-01-infomationleak)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a weak secure algorithm vulnerability in Huawei products.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A weak secure algorithm is used in a module. Attackers can
  exploit this vulnerability by capturing and analyzing the messages between devices to obtain
  information. This can lead to an information leak.");

  script_tag(name:"impact", value:"Attackers can exploit this vulnerability by capturing and
  analyzing the messages between devices to obtain information. This can lead to an information
  leak.");

  script_tag(name:"affected", value:"IPS Module versions V500R005C00SPC100 V500R005C00SPC200

  NGFW Module versions V500R005C00SPC100 V500R005C00SPC200

  Secospace USG6300 versions V500R001C30SPC200 V500R001C30SPC600 V500R001C60SPC500
  V500R005C00SPC100 V500R005C00SPC200

  Secospace USG6500 versions V500R001C30SPC200 V500R001C30SPC600 V500R001C60SPC500
  V500R005C00SPC100 V500R005C00SPC200

  Secospace USG6600 versions V500R001C30SPC200 V500R001C30SPC600 V500R001C60SPC500
  V500R005C00SPC100 V500R005C00SPC200

  USG9500 versions V500R001C30SPC200 V500R001C30SPC600 V500R001C60SPC500 V500R005C00SPC100
  V500R005C00SPC200");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20210512-01-infomationleak-en");

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
patch = get_kb_item("huawei/vrp/patch");

if (version =~ "^V500R001C30SPC200" || version =~ "^V500R001C30SPC600" || version =~ "^V500R001C60SPC500" ||
    version =~ "^V500R005C00SPC100" || version =~ "^V500R005C00SPC200") {
  report = report_fixed_ver(installed_version: version, installed_patch: patch,
                            fixed_version: "V500R005C20SPC500");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
