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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143981");
  script_version("2020-05-26T09:23:10+0000");
  script_tag(name:"last_modification", value:"2020-05-29 08:52:53 +0000 (Fri, 29 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-26 09:10:24 +0000 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-15350");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Buffer Overflow Vulnerability (huawei-sa-20171206-01-buffer)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Multiple Huawei products are prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a buffer overflow vulnerability in the Common Open Policy Service
  Protocol (COPS) module of some Huawei products. An unauthenticated, remote attacker could exploit this
  vulnerability by sending specially crafted message to the affected products. The vulnerability is due to
  insufficient input validation of the message, which could result in a buffer overflow. Successful exploit may
  cause some services abnormal.");

  script_tag(name:"impact", value:"Successful exploit may cause some service abnormal.");

  script_tag(name:"affected", value:"Huawei DP300, IPS Module, NGFW Module, NIP6300, NIP6600, NIP6800,
  RP200, SVN5600, SVN5800, SVN5800-C, Secospace USG6300, Secospace USG6500, Secospace USG6600, TE30, TE40, TE50,
  TE60, TP3206 and USG9500.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171206-01-buffer-en");

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

cpe = infos["cpe"];
version = toupper(infos["version"]);

patch = get_kb_item("huawei/vrp/patch");

if (cpe =~ "^cpe:/o:huawei:usg6[356]00_firmware") {
  if (version == "V100R001C10" || version == "V100R001C20" || version == "V100R001C30" ||
      version == "V500R001C00" || version == "V500R001C20" || version == "V500R001C30" ||
      version == "V500R001C50") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V500R001C60SPC300", fixed_patch: "V500R001SPH012");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:usg9500_firmware") {
  if (version == "V500R001C00" || version == "V500R001C20" || version == "V500R001C30" ||
      version == "V500R001C50") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V500R001C60SPC300", fixed_patch: "V500R001SPH012");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
