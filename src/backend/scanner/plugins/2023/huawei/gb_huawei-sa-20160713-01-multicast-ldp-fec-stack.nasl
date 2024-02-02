# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:huawei:cloudengine_12800_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151447");
  script_version("2023-12-26T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-26 05:05:23 +0000 (Tue, 26 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-21 07:44:56 +0000 (Thu, 21 Dec 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-08-03 17:30:00 +0000 (Wed, 03 Aug 2016)");

  script_cve_id("CVE-2016-6178");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Input Validation Vulnerability in Multiple Huawei Products (huawei-sa-20160713-01-multicast-ldp-fec-stack)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is an input validation vulnerability in Huawei multiple
  products.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker with control plane access may exploit this
  vulnerability by crafting a malformed packet.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause a Denial of Service
  or execute arbitrary code.");

  script_tag(name:"affected", value:"CloudEngine 12800 versions V100R003C00, V100R003C10,
  V100R005C00, V100R005C10.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20160713-01-multicast-ldp-fec-stack-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

version = toupper(version);
patch = get_kb_item("huawei/vrp/patch");

if (version =~ "^V100R003C00" || version =~ "^V100R003C10") {
  if (!patch || version_is_less(version: patch, test_version: "V100R003SPH010")) {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: version, fixed_patch: "V100R003SPH010");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^V100R005C00" || version =~ "^V100R005C10") {
  if (!patch || version_is_less(version: patch, test_version: "V100R005SPH006")) {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: version, fixed_patch: "V100R005SPH006");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
