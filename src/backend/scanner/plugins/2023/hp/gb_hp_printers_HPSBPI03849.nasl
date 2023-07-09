# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:hp:";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149825");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-21 05:17:33 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-1329");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Printer RCE Vulnerability (HPSBPI03849)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"Multiple HP printer are prone to a remote code execution (RCE)
  vulnerability when running HP Workpath solutions on potentially affected products.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_8585737-8585769-16/hpsbpi03849");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m577_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m577_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_m578_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m578_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040445")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040445 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m681_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m681_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_m682_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m682_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040453")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040453 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m776_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m776_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040429")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040429 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e57540_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_e57540_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040445")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040445 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e67550_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e67560_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_e67550_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_e67560_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e67650_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e67660_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040453")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040453 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e7742[2-8]_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040434")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040434 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e77822_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e77825_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e77830_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_e77822_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_e77825_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_e77830_firmware" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e7822[2-8]_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_e78323_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_e78330_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040436")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040436 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e785dn_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e78523_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e78528_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040425")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040425 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e87640_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e87650_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e87660_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_e87640_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_e87650_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_e87660_firmware" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e876[4-6]0du_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040444")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040444 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e877_firmware" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e877[4567]0" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_flow_e877[4567]0") {
  if (version_is_less(version: version, test_version: "2506649.040454")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040454 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m527_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_m527z_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040432")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040432 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_m528_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040437")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040437 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:laserjet_mfp_m63[1-6]_firmware" ||
    cpe == "^cpe:/o:hp:laserjet_flow_mfp_m63[1-6]_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040442")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040442 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_e52545_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e52545c_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040432")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040432 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_e52645_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040437")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040437 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_e62555_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_e62565_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_e62655_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_e62665_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e62555_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e62565_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e62575_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e62675_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040442")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040442 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_e72425_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_e72430_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040451")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040451 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_e72525_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_e72530_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_e72535_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e72525_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e72530_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e72535_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040430")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040430 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_e730_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_e73025_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_e73030_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040435")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040435 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_e731_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e731_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_e73130_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_e73135_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_e73140_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e73130_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e73135_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e73140_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040417")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040417 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_e82540_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_e82550_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_e82560_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e82540_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e82550_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e82560_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_e82540_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_e82550_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_e82560du_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040416")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040416 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:laserjet_mfp_e826dn_firmware" ||
    cpe == "cpe:/o:hp:laserjet_flow_mfp_e826z_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_e82650_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_e82660_firmware" ||
    cpe == "cpe:/o:hp:laserjet_mfp_e82670_firmware" ||
    cpe == "cpe:/o:hp:laserjet_e82650_firmware" ||
    cpe == "cpe:/o:hp:laserjet_e82660_firmware" ||
    cpe == "cpe:/o:hp:laserjet_e82670_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040423")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040423 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_mfp_586_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_flow_mfp_586z_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040414")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040414 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_mfp_774_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_mfp_779_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040454")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040454 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_flow_mfp_785_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_mfp_780_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_flow_mfp_780f_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040424")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040424 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_mfp_e58650dn_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_flow_mfp_e58650z_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040414")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040414 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_mfp_e77650_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_flow_mfp_e77650_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_flow_mfp_e77660z_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040424")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040424 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:pagewide_color_mfp_p77940_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_mfp_p77950_firmware" ||
    cpe == "cpe:/o:hp:pagewide_color_mfp_p77960_firmware") {
  if (version_is_less(version: version, test_version: "2506649.040454")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2506649_040454 (5.6.0.2)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(0);
