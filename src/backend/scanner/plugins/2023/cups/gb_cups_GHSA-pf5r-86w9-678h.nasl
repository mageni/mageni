# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openprinting:cups";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151040");
  script_version("2023-09-26T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-09-26 05:05:30 +0000 (Tue, 26 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-25 04:47:50 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2023-4504");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CUPS < 2.4.7 Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_cups_http_detect.nasl");
  script_mandatory_keys("cups/detected");

  script_tag(name:"summary", value:"CUPS is prone to a heap-based buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to failure in validating the length provided by an
  attacker-crafted PPD PostScript document, CUPS and libppd are susceptible to a heap-based buffer
  overflow and possibly code execution.");

  script_tag(name:"affected", value:"CUPS version 2.4.6 and prior.");

  script_tag(name:"solution", value:"Update to version 2.4.7 or later.");

  script_xref(name:"URL", value:"https://github.com/OpenPrinting/cups/security/advisories/GHSA-pf5r-86w9-678h");
  script_xref(name:"URL", value:"https://github.com/OpenPrinting/cups/releases/tag/v2.4.7");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.4.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
