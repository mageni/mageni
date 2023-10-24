# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170608");
  script_version("2023-10-20T16:09:12+0000");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-18 19:13:34 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-12 16:00:00 +0000 (Thu, 12 Oct 2023)");

  script_cve_id("CVE-2023-3550", "CVE-2023-45360", "CVE-2023-45362", "CVE-2023-45363");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki < 1.35.12, 1.36.x < 1.39.5, 1.40.x < 1.40.1 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-3550: Stored XSS when uploading crafted XML file to Special:Upload (non-standard
  configuration).

  - CVE-2023-45360: XSS via 'youhavenewmessagesmanyusers' and 'youhavenewmessages' messages.

  - CVE-2023-45362: diff-multi-sameuser ignores username suppression.

  - CVE-2023-45363: Infinite loop for self-redirects with variants conversion.");

  script_tag(name:"affected", value:"MediaWiki prior to version 1.35.12, versions 1.36.x through
  1.39.4 and 1.40.");

  script_tag(name:"solution", value:"Update to version 1.35.12, 1.39.5, 1.40.1 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/mediawiki-announce@lists.wikimedia.org/message/BRWOWACCHMYRIS7JRTT6XD44X3362MVL/");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T340221");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T341529");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T333050");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T341565");

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

if (version_is_less(version: version, test_version: "1.35.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.35.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.36.0", test_version2: "1.39.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.39.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "1.40.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.40.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
