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
  script_oid("1.3.6.1.4.1.25623.1.0.144309");
  script_version("2020-07-27T01:28:33+0000");
  script_tag(name:"last_modification", value:"2020-07-27 09:32:59 +0000 (Mon, 27 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-24 02:00:39 +0000 (Fri, 24 Jul 2020)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2020-9101");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Out-of-bounds Write Vulnerability in Some Huawei Products (huawei-sa-20200715-01-outofboundswrite)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Multiple Huawei products are prone to an out of bounds vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An unauthenticated attacker crafts malformed packets with specific parameter
  and sends the packets to the affected products. Due to insufficient validation of packets, which may be exploited
  to cause the process reboot.");

  script_tag(name:"impact", value:"By exploiting this vulnerability, the attacker can cause the process reboot.");

  script_tag(name:"affected", value:"Huawei IPS Module, NGFW Module, Secospace USG6300, Secospace USG6500,
  Secospace USG6600 and USG9500.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20200715-01-outofboundswrite-en");

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

if (version =~ "^V500R001C30" || version =~ "^V500R001C60" || version =~ "^V500R005C00" ||
    version =~ "^V500R005C10") {
  report = report_fixed_ver(installed_version: version, fixed_version: "V500R005C20SPC500");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
