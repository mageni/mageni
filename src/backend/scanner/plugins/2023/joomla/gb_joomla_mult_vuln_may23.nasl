# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149730");
  script_version("2023-06-01T09:09:48+0000");
  script_tag(name:"last_modification", value:"2023-06-01 09:09:48 +0000 (Thu, 01 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-05-31 04:18:44 +0000 (Wed, 31 May 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2023-23754", "CVE-2023-23755");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! 4.2.0 - 4.3.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exit:

  - CVE-2023-23754: Open redirects and XSS within the mfa selection

  - CVE-2023-23755: Bruteforce prevention within the mfa screen");

  script_tag(name:"affected", value:"Joomla! version 4.2.0 through 4.3.1.");

  script_tag(name:"solution", value:"Update to version 4.3.2 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/899-20230501-core-open-redirects-and-xss-within-the-mfa-selection.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/900-20230502-core-bruteforce-prevention-within-the-mfa-screen.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "4.2.0", test_version2: "4.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
