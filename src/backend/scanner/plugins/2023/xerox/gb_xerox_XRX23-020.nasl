# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151335");
  script_version("2023-12-01T16:11:30+0000");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-01 02:58:08 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Xerox Printers Multiple Vulnerabilities (XRX23-020)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_xerox_printer_consolidation.nasl");
  script_mandatory_keys("xerox/printer/detected");

  script_tag(name:"summary", value:"Multiple Xerox printers are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"Cross-site scripting (XSS) and broken access control.");

  script_tag(name:"affected", value:"Xerox AltaLink, VersaLink and WorkCentre printers.

  See the referenced vendor advisory for affected models.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://security.business.xerox.com/wp-content/uploads/2023/11/XRX23-020_Security-Bulletin-for-AltaLink-VersaLink-and-WorkCentre.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:xerox:altalink_b8145_firmware",
                     "cpe:/o:xerox:altalink_b8155_firmware",
                     "cpe:/o:xerox:altalink_c8170_firmware",
                     "cpe:/o:xerox:altalink_c8130_firmware",
                     "cpe:/o:xerox:altalink_c8135_firmware",
                     "cpe:/o:xerox:altalink_c8145_firmware",
                     "cpe:/o:xerox:altalink_c8155_firmware",
                     "cpe:/o:xerox:versalink_b415_firmware",
                     "cpe:/o:xerox:versalink_c415_firmware",
                     "cpe:/o:xerox:versalink_b620_firmware",
                     "cpe:/o:xerox:versalink_b625_firmware",
                     "cpe:/o:xerox:versalink_c625_firmware",
                     "cpe:/o:xerox:workcentre_3655_firmware",
                     "cpe:/o:xerox:workcentre_5845_firmware",
                     "cpe:/o:xerox:workcentre_5890_firmware",
                     "cpe:/o:xerox:workcentre_5945_firmware",
                     "cpe:/o:xerox:workcentre_5955_firmware",
                     "cpe:/o:xerox:workcentre_6655_firmware",
                     "cpe:/o:xerox:workcentre_7845_firmware",
                     "cpe:/o:xerox:workcentre_7855_firmware",
                     "cpe:/o:xerox:workcentre_7830_firmware",
                     "cpe:/o:xerox:workcentre_7835_firmware",
                     "cpe:/o:xerox:workcentre_7970_firmware",
                     "cpe:/o:xerox:workcentre_ec7836_firmware",
                     "cpe:/o:xerox:workcentre_ec7856_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = infos["version"];

if (cpe == "cpe:/o:xerox:altalink_b8145_firmware" ||
    cpe == "cpe:/o:xerox:altalink_b8155_firmware") {
  if (version_is_less(version: version, test_version: "120.013.023.30800")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "120.013.023.30800");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:altalink_c8170_firmware") {
  if (version_is_less(version: version, test_version: "120.011.023.30800")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "120.011.023.30800");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:altalink_c8130_firmware" ||
    cpe == "cpe:/o:xerox:altalink_c8135_firmware" ||
    cpe == "cpe:/o:xerox:altalink_c8145_firmware" ||
    cpe == "cpe:/o:xerox:altalink_c8155_firmware") {
  if (version_is_less(version: version, test_version: "120.010.023.30800")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "120.010.023.30800");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:versalink_b415_firmware") {
  if (version_is_less(version: version, test_version: "120.029.023.30800")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "120.029.023.30800");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:versalink_c415_firmware") {
  if (version_is_less(version: version, test_version: "120.028.023.30800")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "120.028.023.30800");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:versalink_b620_firmware") {
  if (version_is_less(version: version, test_version: "120.027.023.30800")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "120.027.023.30800");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:versalink_b625_firmware") {
  if (version_is_less(version: version, test_version: "120.025.023.30800")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "120.025.023.30800");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:versalink_c625_firmware") {
  if (version_is_less(version: version, test_version: "120.024.023.30800")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "120.024.023.30800");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_3655_firmware" ||
    cpe == "cpe:/o:xerox:workcentre_5845_firmware" ||
    cpe == "cpe:/o:xerox:workcentre_5890_firmware") {
  if (version_is_less(version: version, test_version: "075.060.013.29000")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "075.060.013.29000");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_5945_firmware" ||
    cpe == "cpe:/o:xerox:workcentre_5955_firmware") {
  if (version_is_less(version: version, test_version: "075.091.013.29000")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "075.091.013.29000");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_6655_firmware") {
  if (version_is_less(version: version, test_version: "075.110.013.29000")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "075.110.013.29000");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_7845_firmware" ||
    cpe == "cpe:/o:xerox:workcentre_7855_firmware") {
  if (version_is_less(version: version, test_version: "075.040.013.29000")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "075.040.013.29000");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_7830_firmware" ||
    cpe == "cpe:/o:xerox:workcentre_7835_firmware") {
  if (version_is_less(version: version, test_version: "075.010.013.29000")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "075.010.013.29000");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_7970_firmware") {
  if (version_is_less(version: version, test_version: "075.200.013.29000")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "075.200.013.29000");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_ec7836_firmware") {
  if (version_is_less(version: version, test_version: "075.050.013.29000")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "075.050.013.29000");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_ec7856_firmware") {
  if (version_is_less(version: version, test_version: "075.020.013.29000")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "075.020.013.29000");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
