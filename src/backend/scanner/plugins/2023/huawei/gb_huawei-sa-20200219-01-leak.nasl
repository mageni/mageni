# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:huawei:cloudengine_12800_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151445");
  script_version("2023-12-26T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-26 05:05:23 +0000 (Tue, 26 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-21 07:18:08 +0000 (Thu, 21 Dec 2023)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-04 15:09:00 +0000 (Wed, 04 Mar 2020)");

  script_cve_id("CVE-2020-1861");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Information Leakage Vulnerability in Some Huawei Products (huawei-sa-20200219-01-leak)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is an information leakage vulnerability in some Huawei
  products.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In some special cases, an authenticated attacker can exploit
  this vulnerability because the software processes data improperly.");

  script_tag(name:"impact", value:"Successful exploitation may lead to information leakage.");

  script_tag(name:"affected", value:"CloudEngine 12800 versions V200R001C00SPC600,
  V200R001C00SPC700, V200R002C01, V200R002C50SPC800, V200R002C50SPC800PWE, V200R003C00SPC810,
  V200R003C00SPC810PWE, V200R005C00SPC600, V200R005C00SPC800, V200R005C00SPC800PWE,
  V200R005C10, V200R005C10SPC300.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20200219-01-leak-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

version = toupper(version);

if (version =~ "^V200R001C00SPC600" || version =~ "^V200R001C00SPC700" ||
    version =~ "^V200R002C01" || version =~ "^V200R002C50SPC800" || version =~ "^V200R003C00SPC810" ||
    version =~ "^V200R005C00SPC600" || version =~ "^V200R005C00SPC800" || version =~ "^V200R005C10") {
  report = report_fixed_ver(installed_version: version, fixed_version: "V200R005C10SPC800");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
