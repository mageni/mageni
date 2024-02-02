# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124496");
  script_version("2024-01-22T05:07:31+0000");
  script_tag(name:"last_modification", value:"2024-01-22 05:07:31 +0000 (Mon, 22 Jan 2024)");
  script_tag(name:"creation_date", value:"2023-12-27 07:28:12 +0000 (Wed, 27 Dec 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-29 19:01:00 +0000 (Fri, 29 Dec 2023)");

  script_cve_id("CVE-2023-51704");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki < 1.35.14, 1.36.x < 1.39.6, 1.40.x < 1.40.2 XSS Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MediaWiki is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Messages related to group memberships (group-*-member) within
  includes/logging/RightsLogFormatter.php are susceptible to cross-site scripting attacks due to
  inadequate escape handling.");

  script_tag(name:"affected", value:"MediaWiki prior to version 1.35.14, version 1.36.x prior to
  1.39.6 and 1.40.x prior to 1.40.2.");

  script_tag(name:"solution", value:"Update to version 1.35.14, 1.39.6, 1.40.2 or later.");

  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/cve-2023-51704");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T347726");

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

if (version_is_less(version:version, test_version:"1.35.14")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.35.14", install_path:location);
  security_message(data:report, port:port);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.36.0", test_version_up: "1.39.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: " 1.39.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.39.0", test_version_up: "1.40.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.40.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
