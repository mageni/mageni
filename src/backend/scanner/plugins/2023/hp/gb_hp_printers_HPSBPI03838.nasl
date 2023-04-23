# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:hp:";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149519");
  script_version("2023-04-18T10:10:05+0000");
  script_tag(name:"last_modification", value:"2023-04-18 10:10:05 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-18 03:53:58 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_cve_id("CVE-2023-1707");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Printer Information Disclosure Vulnerability (HPSBPI03838)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"Multiple HP printer are prone to an information disclosure
  vulnerability when IPSec is enabled with FutureSmart version 5.6.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_7905330-7905358-16/hpsbpi03838");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe == "cpe:/o:hp:color_laserjet_5700_firmware") {
  if (version_is_less(version: version, test_version: "2505701.000874")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000874 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m5800_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m5800_firmware") {
  if (version_is_less(version: version, test_version: "2505701.000860")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000860 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_6700_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_6701_firmware") {
  if (version_is_less(version: version, test_version: "2505701.000873")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000873 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m6800_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m6800_firmware") {
  if (version_is_less(version: version, test_version: "2505701.000852")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000852 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_m455_firmware") {
  if (version_is_less(version: version, test_version: "2505701.000841")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000841 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m480_firmware") {
  if (version_is_less(version: version, test_version: "2505701.000855")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000855 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_e45028_firmware") {
  if (version_is_less(version: version, test_version: "2505701.000841")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000841 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e47528_firmware") {
  if (version_is_less(version: version, test_version: "2505701.000855")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000855 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e785dn_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e78523_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e78528_firmware") {
  if (version_is_less(version: version, test_version: "2505701.000844")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000844 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e786_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e78625_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e78630_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e78635_firmware") {
  if (version_is_less(version: version, test_version: "2505701.000849")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000849 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e877_firmware" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e877[4567]0" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_flow_e877[4567]0") {
  if (version_is_less(version: version, test_version: "2505701.000865")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000865 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_x55745_firmware") {
  if (version_is_less(version: version, test_version: "2505701.000874")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000874 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_x57945_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_x57945_firmware") {
  if (version_is_less(version: version, test_version: "2505701.000860")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000860 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_m406_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_m407_firmware") {
  if (version_is_less(version: version, test_version: "2505701.000839")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000839 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_m430_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_m431_firmware") {
  if (version_is_less(version: version, test_version: "2505701.000834")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000834 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_e40040_firmware") {
  if (version_is_less(version: version, test_version: "2505701.000839")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000839 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e42540_firmware") {
  if (version_is_less(version: version, test_version: "2505701.000834")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000834 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e730_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e73025_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_mfp_e73030_firmware") {
  if (version_is_less(version: version, test_version: "2505701.000868")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000868 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e731_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_m731_firmware" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e731(30|35|40)" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_flow_mfp_e731(30|35|40)") {
  if (version_is_less(version: version, test_version: "2505701.000853")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000853 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:color_laserjet_mfp_e826dn_firmware" ||
    cpe == "cpe:/o:hp:color_laserjet_flow_mfp_e826z_firmware" ||
    cpe =~ "^cpe:/o:hp:color_laserjet_mfp_e826[567]0") {
  if (version_is_less(version: version, test_version: "2505701.000850")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2505701_000850 (5.5.0.3)");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(0);
