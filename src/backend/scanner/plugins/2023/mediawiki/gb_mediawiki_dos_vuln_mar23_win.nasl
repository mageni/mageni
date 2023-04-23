# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124302");
  script_version("2023-04-12T11:20:00+0000");
  script_tag(name:"last_modification", value:"2023-04-12 11:20:00 +0000 (Wed, 12 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-05 08:04:40 +0000 (Wed, 05 Apr 2023)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2020-36649", "CVE-2023-29141");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki < 1.35.10, 1.36.x < 1.38.6, 1.39.x < 1.39.3 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_mediawiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-36649: Bundled PapaParse copy in VisualEditor has known ReDos.

  - CVE-2023-29141: X-Forwarded-For header allows brute-forcing autoblocked IP addresses.

  - CVE-2023-PENDING: OATHAuth allows replay attacks when MediaWiki is configured without
  ObjectCache Insecure Default Configuration.");

  #todo replace correct CVE once was published.

  script_tag(name:"affected", value:"MediaWiki versions prior to 1.35.10, 1.36.x prior to 1.38.6,
  1.39.x prior to 1.39.3");

  script_tag(name:"solution", value:"Update to version 1.35.10, 1.38.6, 1.39.3 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/mediawiki-announce@lists.wikimedia.org/thread/6UQBHI5FWLATD7QO7DI4YS54U7XSSLAN/");

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

if (version_is_less(version: version, test_version: "1.35.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.35.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.36.0", test_version_up: "1.38.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.38.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.39.0", test_version_up: "1.39.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.39.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
