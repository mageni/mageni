# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pi-hole:web_interface";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114200");
  script_version("2023-12-01T16:11:30+0000");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-30 16:25:15 +0000 (Thu, 30 Nov 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-24 19:56:00 +0000 (Fri, 24 Sep 2021)");

  script_cve_id("CVE-2021-3706", "CVE-2021-3811", "CVE-2021-3812");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pi-hole Web Interface <= 5.5.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pi-hole_http_detect.nasl");
  script_mandatory_keys("pi-hole/detected");

  script_tag(name:"summary", value:"The Pi-hole Web Interface (previously AdminLTE) is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2021-3706: Sensitive Cookie Without 'HttpOnly' Flag

  - CVE-2021-3811, CVE-2021-3812: Cross-site Scripting (XSS) - Reflected");

  script_tag(name:"affected", value:"Pi-hole Web Interface (previously AdminLTE) versions 5.5.1 and
  prior.");

  script_tag(name:"solution", value:"Update to version 5.6 or later.");

  script_xref(name:"URL", value:"https://github.com/pi-hole/web/security/advisories/GHSA-9hfp-j66v-6q3j");
  script_xref(name:"URL", value:"https://huntr.com/bounties/ac7fd77b-b31b-4d02-aebd-f89ecbae3fce/");
  script_xref(name:"URL", value:"https://github.com/pi-hole/web/security/advisories/GHSA-5q5w-qm5m-49qq");
  script_xref(name:"URL", value:"https://huntr.com/bounties/fa38c61f-4043-4872-bc85-7fe5ae5cc2e8/");
  script_xref(name:"URL", value:"https://github.com/pi-hole/web/security/advisories/GHSA-3gfp-33g5-4cqq");
  script_xref(name:"URL", value:"https://huntr.com/bounties/875a6885-9a64-46f3-94ad-92f40f989200/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "5.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
