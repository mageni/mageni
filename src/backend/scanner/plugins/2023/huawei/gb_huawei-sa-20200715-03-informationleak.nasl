# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104917");
  script_version("2023-09-15T16:10:33+0000");
  script_tag(name:"last_modification", value:"2023-09-15 16:10:33 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-15 09:38:52 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-23 18:28:00 +0000 (Thu, 23 Jul 2020)");

  script_cve_id("CVE-2020-9102");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Information Disclosure Vulnerability on some Huawei Products (huawei-sa-20200715-03-informationleak)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a information leak vulnerability in some Huawei
  products, and it could allow a local attacker to get information.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to the improper management of the username.");

  script_tag(name:"impact", value:"An attacker with the ability to access the device and cause the
  username information leak.");

  script_tag(name:"affected", value:"CloudEngine 16800 versions V200R005C20SPC800, V200R019C00SPC800

  CloudEngine 12800 versions V200R002C50SPC800, V200R003C00SPC810, V200R005C00SPC800,
  V200R005C10SPC800, V200R019C00SPC800

  CloudEngine 5800 versions V200R002C50SPC800, V200R003C00SPC810, V200R005C00SPC800,
  V200R005C10SPC800, V200R019C00SPC800

  CloudEngine 6800 versions V200R002C50SPC800, V200R003C00SPC810, V200R005C00SPC800,
  V200R005C10SPC800, V200R005C20SPC800, V200R019C00SPC800

  CloudEngine 7800 versions V200R002C50SPC800, V200R003C00SPC810, V200R005C00SPC800,
  V200R005C10SPC800, V200R019C00SPC800

  CloudEngine 8800 versions V200R002C50SPC800, V200R003C00SPC810, V200R005C00SPC800,
  V200R005C10SPC800, V200R019C00SPC800");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20200715-03-informationleak-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:cloudengine_16800_firmware",
                     "cpe:/o:huawei:cloudengine_12800_firmware",
                     "cpe:/o:huawei:cloudengine_5800_firmware",
                     "cpe:/o:huawei:cloudengine_6800_firmware",
                     "cpe:/o:huawei:cloudengine_7800_firmware",
                     "cpe:/o:huawei:cloudengine_8800_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);
patch = get_kb_item("huawei/vrp/patch");

if (cpe == "cpe:/o:huawei:cloudengine_16800_firmware") {
  if (version =~ "^V200R005C20SPC800" || version =~ "^V200R019C00SPC800") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R019C10SPC800");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:cloudengine_12800_firmware") {
  if (version =~ "^V200R002C50SPC800" || version =~ "^V200R003C00SPC810" || version =~ "^V200R005C00SPC800") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R005C10SPC800", fixed_patch: "V200R005SPH023");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version =~ "^V200R005C10SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R005SPH023")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch,
                                fixed_version: "V200R005C10SPC800", fixed_patch: "V200R005SPH023");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (version =~ "^V200R019C00SPC800") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R019C10SPC800");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:cloudengine_5800_firmware") {
  if (version =~ "^V200R002C50SPC800" || version =~ "^V200R003C00SPC810" || version =~ "^V200R005C00SPC800") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R005C10SPC800", fixed_patch: "V200R005SPH023");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version =~ "^V200R005C10SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R005SPH023")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch,
                                fixed_version: "V200R005C10SPC800", fixed_patch: "V200R005SPH023");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (version =~ "^V200R019C00SPC800") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R019C10SPC800");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:cloudengine_6800_firmware") {
  if (version =~ "^V200R002C50SPC800" || version =~ "^V200R003C00SPC810" || version =~ "^V200R005C00SPC800") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R005C10SPC800", fixed_patch: "V200R005SPH025");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version =~ "^V200R005C10SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R005SPH025")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch,
                                fixed_version: "V200R005C10SPC800", fixed_patch: "V200R005SPH025");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (version =~ "^V200R005C20SPC800" || version =~ "^V200R019C00SPC800") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R019C10SPC800");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:cloudengine_7800_firmware") {
  if (version =~ "^V200R002C50SPC800" || version =~ "^V200R003C00SPC810" || version =~ "^V200R005C00SPC800") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R005C10SPC800", fixed_patch: "V200R005SPH025");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version =~ "^V200R005C10SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R005SPH025")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch,
                                fixed_version: "V200R005C10SPC800", fixed_patch: "V200R005SPH025");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (version =~ "^V200R019C00SPC800") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R019C10SPC800");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:huawei:cloudengine_8800_firmware") {
  if (version =~ "^V200R002C50SPC800" || version =~ "^V200R003C00SPC810" || version =~ "^V200R005C00SPC800") {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "V200R005C10SPC800", fixed_patch: "V200R005SPH025");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version =~ "^V200R005C10SPC800") {
    if (!patch || version_is_less(version: patch, test_version: "V200R005SPH025")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch,
                                fixed_version: "V200R005C10SPC800", fixed_patch: "V200R005SPH025");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (version =~ "^V200R019C00SPC800") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R019C10SPC800");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
