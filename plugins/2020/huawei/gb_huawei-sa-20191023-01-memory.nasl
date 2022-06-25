# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.143121");
  script_version("2020-06-05T06:56:36+0000");
  script_tag(name:"last_modification", value:"2020-06-05 10:05:11 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"creation_date", value:"2019-11-14 04:35:54 +0000 (Thu, 14 Nov 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2019-5293");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Memory Leak Vulnerability in Some Huawei Products (huawei-sa-20191023-01-memory)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a memory leak vulnerability in some Huawei products.");

  script_tag(name:"insight", value:"A remote attacker with operation privilege could exploit the vulnerability by
  sending specific messages continuously.");

  script_tag(name:"impact", value:"Successful exploit may cause some service abnormal.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Huawei AR150, AR160, AR200, AR1200, AR2200, AR3200, AR3600, SRG1300, SRG2300
  and SRG3300.");

  script_tag(name:"solution", value:"See the vendors advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20191023-01-memory-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:ar150_firmware",
                     "cpe:/o:huawei:ar160_firmware",
                     "cpe:/o:huawei:ar200_firmware",
                     "cpe:/o:huawei:ar1200_firmware",
                     "cpe:/o:huawei:ar2200_firmware",
                     "cpe:/o:huawei:ar3200_firmware",
                     "cpe:/o:huawei:ar3600_firmware",
                     "cpe:/o:huawei:srg1300_firmware",
                     "cpe:/o:huawei:srg2300_firmware",
                     "cpe:/o:huawei:srg3300_firmware");

if (!infos = get_app_port_from_list(cpe_list: cpe_list))
  exit(0);

cpe = infos["cpe"];
port = infos["port"];

if (!version = get_app_version(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

if (version_is_greater_equal(version: version, test_version: "v200r005c20") &&
    version_is_less(version: version, test_version: "v200r007c00spcb00")) {
  report = report_fixed_ver(installed_version: toupper(version), fixed_version: "V200R007C00SPCb00");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(99);
