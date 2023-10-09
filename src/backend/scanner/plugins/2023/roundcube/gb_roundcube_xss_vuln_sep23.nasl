# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:roundcube:webmail";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151035");
  script_version("2023-09-26T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-09-26 05:05:30 +0000 (Tue, 26 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-25 03:02:08 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2023-43770");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Roundcube Webmail < 1.4.14, 1.5.x < 1.5.4, 1.6.x < 1.6.3 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_roundcube_http_detect.nasl");
  script_mandatory_keys("roundcube/detected");

  script_tag(name:"summary", value:"Roundcube Webmail is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Roundcube allows XSS via text/plain e-mail messages with
  crafted links because of program/lib/Roundcube/rcube_string_replacer.php behavior.");

  script_tag(name:"affected", value:"Roundcube Webmail prior to version 1.4.14, 1.5.x through
  1.5.3 and 1.6.x through 1.6.2.");

  script_tag(name:"solution", value:"Update to version 1.4.14, 1.5.4, 1.6.3 or later.");

  script_xref(name:"URL", value:"https://roundcube.net/news/2023/09/15/security-update-1.6.3-released");
  script_xref(name:"URL", value:"https://roundcube.net/news/2023/09/18/security-update-1.5.4-released");
  script_xref(name:"URL", value:"https://roundcube.net/news/2023/09/18/security-update-1.4.14-released");

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

if (version_is_less(version: version, test_version: "1.4.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.5", test_version_up: "1.5.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.6", test_version_up: "1.6.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.6.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
