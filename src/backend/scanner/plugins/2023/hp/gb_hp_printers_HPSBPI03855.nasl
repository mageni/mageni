# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:hp:";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170521");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-25 19:46:20 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

  script_cve_id("CVE-2023-26301");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Printer Elevation of Privilege and/or Information Disclosure Vulnerability (HPSBPI03855)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"Multiple HP printer are prone to elevation of privilege and
  information disclosure vulnerabilities related to a lack of authentication with certain endpoints.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/ish_8746769-8746795-16/hpsbpi03855");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe =~ "cpe:/o:hp:laserjet_pro_420[1-3](|cdn|dn|dw)_firmware") {
  if (version_is_less(version: version, test_version: "6.12.1.12-202306030312")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.12.1.12-202306030312");
    security_message(port: 0, data: report);
    exit(0);
  }
}
# HP Color LaserJet Pro MFP 4301-4303dw/fdn/fdw Printer Series
if (cpe =~ "cpe:/o:hp:laserjet_pro_mfp_430[1-3](|dw|fdn|fdw)_firmware") {
  if (version_is_less(version: version, test_version: "6.12.1.12-202306030312")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.12.1.12-202306030312");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
