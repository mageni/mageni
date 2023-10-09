# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zope:zope";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151105");
  script_version("2023-10-06T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-06 02:50:56 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2023-42458");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zope XSS Vulnerability (GHSA-wm8q-9975-xh5v)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_zope_http_detect.nasl");
  script_mandatory_keys("zope/detected");

  script_tag(name:"summary", value:"Zope is prone to a cross-site scripting (XSS) vulnerability
  with SVG images.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a stored cross site scripting vulnerability for SVG
  images.

  Note that an image tag with an SVG image as source is never vulnerable, even when the SVG image
  contains malicious code. To exploit the vulnerability, an attacker would first need to upload an
  image, and then trick a user into following a specially crafted link.");

  script_tag(name:"affected", value:"Zope version 4.8.9 and prior and version 5.x through 5.8.4.");

  script_tag(name:"solution", value:"Update to version 4.8.10, 5.8.5 or later.");

  script_xref(name:"URL", value:"https://github.com/zopefoundation/Zope/security/advisories/GHSA-wm8q-9975-xh5v");

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

if (version_is_less(version: version, test_version: "4.8.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.8.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.8.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
