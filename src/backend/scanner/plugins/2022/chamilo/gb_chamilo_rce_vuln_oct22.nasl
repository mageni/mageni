# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:chamilo:chamilo_lms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126316");
  script_version("2023-06-01T09:09:48+0000");
  script_tag(name:"last_modification", value:"2023-06-01 09:09:48 +0000 (Thu, 01 Jun 2023)");
  # nb: This was initially a single VT but got split later into multiple due to different affected /
  # fixed versions. Thus the original creation_date of the first VT has been kept.
  script_tag(name:"creation_date", value:"2022-09-30 08:47:25 +0000 (Fri, 30 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-08 12:15:00 +0000 (Wed, 08 Jan 2020)");

  script_cve_id("CVE-2019-20041", "CVE-2022-27426", "CVE-2022-42029");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Chamilo LMS < 1.11.18 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_chamilo_http_detect.nasl");
  script_mandatory_keys("chamilo/detected");

  script_tag(name:"summary", value:"Chamilo LMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2019-20041 / Issue #91: XSS Vulnerability in HTML5 strings sanitization

  - CVE-2022-27426 / Issue #93: An attacker is able to enumerate the internal network and execute
  arbitrary system commands via a crafted Phar file

  - CVE-2022-42029 / Issue #95: Big file uploads could copy/move local files out of the Chamilo
  directory");

  script_tag(name:"affected", value:"Chamilo LMS prior to version 1.11.18.");

  script_tag(name:"solution", value:"Update to version 1.11.18 or later.");

  # nb: To "find" the actual fixed version of the flaws the "short" commit IDs needs to be looked up
  # at the following changelog:
  script_xref(name:"URL", value:"https://11.chamilo.org/documentation/changelog.html#1.11.18");

  # CVE-2019-20041 / Issue #91:
  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/commit/56df018a8481e65e8c2f0f3f8858a78aca6c3782");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-91-2021-09-11-Low-impact-Medium-risk-XSS-Vulnerability-in-HTML5-strings-sanitization");

  # CVE-2022-27426 / Issue #93:
  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/commit/640ba55e6c50973e5771969ad9eee71e57024f5c");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-93-2022-03-01-High-impact-Low-risk-SSRF-and-Phar-Deserialization-vulnerability-that-lead-to-remote-code-execution");

  # CVE-2022-42029 / Issue #95:
  script_xref(name:"URL", value:"https://github.com/chamilo/chamilo-lms/commit/b92887c6deb6a802607a071aecb519417e6024fc");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-95-2022-09-14-High-impact-Moderate-risk-Authenticated-Local-file-inclusion");

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

if (version_is_less(version: version, test_version: "1.11.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.11.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
