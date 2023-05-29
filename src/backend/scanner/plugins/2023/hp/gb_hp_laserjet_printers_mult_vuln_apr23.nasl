# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:hp:color_laserjet_pro";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149651");
  script_version("2023-05-08T09:08:51+0000");
  script_tag(name:"last_modification", value:"2023-05-08 09:08:51 +0000 (Mon, 08 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-08 06:13:22 +0000 (Mon, 08 May 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-27971", "CVE-2023-27972", "CVE-2023-27973");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP LaserJet Pro Multiple Vulnerabilities (HPSBPI03839, HPSBPI03840, HPSBPI03841)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"Certain HP LaserJet Pro printers are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-27971: Potential buffer overflow, elevation of privilege

  - CVE-2023-27972: Potential buffer overflow, remote code execution

  - CVE-2023-27973: Potential heap overflow, remote code execution");

  script_tag(name:"affected", value:"- HP Color LaserJet MFP M478-M479 series

  - HP Color LaserJet Pro M453-M454 series

  - HP LaserJet Pro M304-M305 Printer series

  - HP LaserJet Pro M404-M405 Printer series

  - HP LaserJet Pro MFP M428-M429 f series

  - HP LaserJet Pro MFP M428-M429 series");

  script_tag(name:"solution", value:"Update to firmware version 002_2310A or later.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_7919962-7920003-16/hpsbpi03839");
  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_7920078-7920104-16/hpsbpi03840");
  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_7920137-7920161-16/hpsbpi03841");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

# e.g. SHMNT2XXXN002.2310A.00
check_vers = substr(version, 10, 18);

if (cpe =~ "^cpe:/h:hp:color_laserjet_pro_mfp_m47[89]" ||
    cpe =~ "^cpe:/h:hp:color_laserjet_pro_m45[34]" ||
    cpe =~ "^cpe:/h:hp:laserjet_pro_m30[45]" ||
    cpe =~ "^cpe:/h:hp:laserjet_pro_m40[45]" ||
    cpe =~ "^cpe:/h:hp:laserjet_pro_mfp_m42[89]") {
  if (version_is_less(version: check_vers, test_version: "002.2310a")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "002_2310A");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
