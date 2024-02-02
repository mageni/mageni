# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151441");
  script_version("2023-12-26T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-26 05:05:23 +0000 (Tue, 26 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-21 05:35:53 +0000 (Thu, 21 Dec 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-31 15:18:00 +0000 (Thu, 31 Dec 2020)");

  script_cve_id("CVE-2020-9124");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Memory Leak Vulnerability in Huawei CloudEngine Product (huawei-sa-20201223-01-cloudengine)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a memory leak vulnerability in Huawei CloudEngine
  product.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An unauthenticated, remote attacker may exploit this
  vulnerability by sending specific message to the affected product.");

  script_tag(name:"impact", value:"Due to not release the allocated memory properly, successful
  exploit may cause memory leak.");

  script_tag(name:"affected", value:"CloudEngine 12800 versions V200R002C50SPC800,
  V200R003C00SPC810, V200R005C00SPC800, V200R005C10SPC800

  CloudEngine 5800 versions V200R002C50SPC800, V200R003C00SPC810, V200R005C00SPC800,
  V200R005C10SPC800

  CloudEngine 6800 versions V200R002C50SPC800, V200R003C00SPC810, V200R005C00SPC800,
  V200R005C10SPC800

  CloudEngine 7800 versions V200R002C50SPC800, V200R003C00SPC810, V200R005C00SPC800,
  V200R005C10SPC800");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20201223-01-cloudengine-en");

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

if (version =~ "^V200R002C50SPC800" || version =~ "^V200R003C00SPC810" ||
    version =~ "^V200R005C00SPC800" || version =~ "^V200R005C10SPC800") {
  if (!patch || version_is_less(version: patch, test_version: "V200R005SPH010")) {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: version, fixed_patch: "V200R005SPH010");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
