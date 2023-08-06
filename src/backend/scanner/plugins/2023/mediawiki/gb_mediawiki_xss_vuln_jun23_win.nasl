# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124347");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-06 10:28:12 +0000 (Thu, 06 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2023-36675");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki < 1.35.11, 1.36.x < 1.38.7, 1.39.x < 1.39.4 XSS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"BlockLogFormatter.php in BlockLogFormatter allows XSS in the
  partial blocks feature.");

  script_tag(name:"affected", value:"MediaWiki prior to version 1.35.11, version 1.36.x prior to
  1.38.7 and 1.39.x prior to 1.39.4.");

  script_tag(name:"solution", value:"Update to version 1.35.11, 1.38.7, 1.39.4, 1.40.0 or later.");

  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T332889");

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

if (version_is_less(version:version, test_version:"1.35.11")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.35.11", install_path:location);
  security_message(data:report, port:port);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.36.0", test_version_up: "1.38.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.38.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.39.0", test_version_up: "1.39.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.39.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
