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

CPE = "cpe:/o:huawei:cloudengine_5800_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147219");
  script_version("2021-11-24T06:36:37+0000");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-24 06:30:53 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2021-39976");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Privilege Escalation Vulnerability in Huawei Product (huawei-sa-20211103-01-privilege)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a privilege escalation vulnerability in some Huawei products.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a privilege escalation vulnerability in some Huawei
  products. Due to lack of privilege restrictions, an authenticated local attacker can perform
  specific operation to exploit this vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation may cause the attacker to obtain a
  higher privilege.");

  script_tag(name:"affected", value:"CloudEngine 5800 versions V200R020C00SPC600");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20211103-01-privilege-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

version = toupper(version);
patch = get_kb_item("huawei/vrp/patch");

if (version =~ "^V200R020C00SPC600") {
  if (!patch || version_is_less(version: patch, test_version: "V200R020SPH008")) {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R020C00SPC600", fixed_patch: "V200R020SPH008");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
