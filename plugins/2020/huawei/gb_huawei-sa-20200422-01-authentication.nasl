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
  script_oid("1.3.6.1.4.1.25623.1.0.150308");
  script_version("2020-10-15T14:37:51+0000");
  script_tag(name:"last_modification", value:"2020-10-16 10:38:09 +0000 (Fri, 16 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-15 13:58:09 +0200 (Thu, 15 Oct 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");

  script_cve_id("CVE-2020-9068");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Improper Authentication Vulnerability in Several Huawei Products (huawei-sa-20200422-01-authentication)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Some Huawei products have an improper authentication vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Some Huawei products have an improper authentication
  vulnerability. Attackers need to perform some operations to exploit the vulnerability. Successful
  exploit may obtain certain permissions on the device.");

  script_tag(name:"impact", value:"Attackers can exploit this vulnerability to obtain certain device permissions.");

  script_tag(name:"affected", value:"AR3200 versions V200R007C00SPC900 V200R007C00SPCa00 V200R007C00SPCb00 V200R007C00SPCc00 V200R009C00SPC500");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20200422-01-authentication-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:ar3200_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:ar3200_firmware")  {
  if(version =~ "^V200R007C00SPC900" || version =~ "^V200R007C00SPCA00" || version =~ "^V200R007C00SPCB00" || version =~ "^V200R007C00SPCC00" || version =~ "^V200R009C00SPC500") {
    if (!patch || version_is_less(version: patch, test_version: "V200R007SPH026")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007SPH026");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit(99);
