# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151446");
  script_version("2023-12-26T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-26 05:05:23 +0000 (Tue, 26 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-21 07:30:46 +0000 (Thu, 21 Dec 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-11 01:14:00 +0000 (Tue, 11 Apr 2017)");

  script_cve_id("CVE-2016-8790");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Buffer Overflow Vulnerability in Some Huawei Products (huawei-sa-20161116-01-cfm)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a buffer overflow vulnerability in Connectivity Fault
  Management (CFM) function of some Huawei Products.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When CFM is enabled and Maintenance Association End Point (MEP)
  is configured on the affected device, an adjacent attacker could exploit this vulnerability by
  sending crafted packets to the affected system.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause the main control
  board of the affected device reboot.");

  script_tag(name:"affected", value:"CloudEngine 5800 versions V100R003C10, V100R005C00,
  V100R005C10, V100R006C00

  CloudEngine 6800 versions V100R003C10, V100R005C00, V100R005C10, V100R006C00

  CloudEngine 7800 versions V100R003C10, V100R005C00, V100R005C10, V100R006C00

  CloudEngine 8800 version V100R006C00

  CloudEngine 12800 versions V100R003C10, V100R005C00, V100R005C10, V100R006C00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20161116-01-cfm-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:cloudengine_12800_firmware",
                     "cpe:/o:huawei:cloudengine_5800_firmware",
                     "cpe:/o:huawei:cloudengine_6800_firmware",
                     "cpe:/o:huawei:cloudengine_7800_firmware",
                     "cpe:/o:huawei:cloudengine_8800_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);

if (cpe == "cpe:/o:huawei:cloudengine_8800_firmware") {
  if (version =~ "^V100R006C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R001C00SPC700");
    security_message(port: 0, data: report);
    exit(0);
  }
}

else {
  if (version =~ "^V100R003C10" || version =~ "^V100R005C00" || version =~ "^V100R005C10" ||
      version =~ "^V100R006C00") {
    report = report_fixed_ver(installed_version: version, fixed_version: "V200R001C00SPC700");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
