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
  script_oid("1.3.6.1.4.1.25623.1.0.146548");
  script_version("2021-08-24T07:48:07+0000");
  script_tag(name:"last_modification", value:"2021-08-24 10:24:50 +0000 (Tue, 24 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-24 07:35:09 +0000 (Tue, 24 Aug 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2021-22328");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Denial of Service Vulnerability in Some Huawei Products (huawei-sa-20210407-01-dos)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a denial of service vulnerability in some Huawei products.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a denial of service vulnerability in some huawei
  products. In specific scenarios, due to the improper handling of the packets, an attacker may
  craft the specific packet. Successful exploit may cause some services abnormal.");

  script_tag(name:"impact", value:"Successful exploit may cause a denial of service.");

  script_tag(name:"affected", value:"CloudEngine 12800 versions V200R005C00SPC800

  CloudEngine 5800 versions V200R005C00SPC800

  CloudEngine 6800 versions V200R005C00SPC800

  CloudEngine 7800 versions V200R005C00SPC800");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20210407-01-dos-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:cloudengine_12800_firmware",
                     "cpe:/o:huawei:cloudengine_5800_firmware",
                     "cpe:/o:huawei:cloudengine_6800_firmware",
                     "cpe:/o:huawei:cloudengine_7800_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if(version =~ "^V200R005C00SPC800") {
  report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R005C10SPC800");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
