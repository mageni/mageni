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
  script_oid("1.3.6.1.4.1.25623.1.0.143949");
  script_version("2020-05-20T09:41:35+0000");
  script_tag(name:"last_modification", value:"2020-05-29 08:52:53 +0000 (Fri, 29 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-20 07:21:29 +0000 (Wed, 20 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-3730", "CVE-2017-3731", "CVE-2017-3732");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: OpenSSL Vulnerabilities (huawei-sa-20170503-01-openssl)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Multiple Huawei products are prone to multiple vulnerabilities in OpenSSL.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"On January 26, 2017, the OpenSSL Software Foundation released a security
  advisory that included three new vulnerabilities. See the referenced vendor advisory for further details.");

  script_tag(name:"affected", value:"Huawei AC6005, AC6605, AP2000, AP3000, AP4000, AP6000, AP7000, IPS Module,
  NGFW Module, OceanStor 9000, OceanStor Backup Software, RH5885 V3, Secospace AntiDDoS8000,
  Secospace AntiDDoS8030, Secospace USG6600, UPS2000, USG9500 and eSpace VCN3000.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20170503-01-openssl-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:usg6600_firmware",
                     "cpe:/o:huawei:usg9500_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);

if (cpe == "cpe:/o:huawei:usg6600_firmware") {
  if (version == "V500R001C30" || version == "V500R001C50" || version == "V500R001C50PWE") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V500R001C30SPC600");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:usg9500_firmware") {
  if (version == "V500R001C30SPC100" || version == "V500R001C30SPC200") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V500R001C30SPC600");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
