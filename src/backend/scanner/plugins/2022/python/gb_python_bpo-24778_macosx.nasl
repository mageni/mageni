# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113931");
  script_version("2023-03-30T15:39:46+0000");
  script_tag(name:"last_modification", value:"2023-03-30 15:39:46 +0000 (Thu, 30 Mar 2023)");
  script_tag(name:"creation_date", value:"2022-04-21 12:40:42 +0000 (Thu, 21 Apr 2022)");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:C/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 17:55:00 +0000 (Wed, 09 Nov 2022)");

  script_cve_id("CVE-2015-20107");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python Shell Command Injection Vulnerability (bpo-24778) - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl");
  script_mandatory_keys("python/mac-os-x/detected");

  script_tag(name:"summary", value:"Python is prone to a shell command injection vulnerability in
  the mailcap module.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In Python (aka CPython) the mailcap module does not add escape
  characters into commands discovered in the system mailcap file. This may allow attackers to inject
  shell commands into applications that call mailcap.findmatch with untrusted input (if they lack
  validation of user-provided filenames or arguments).");

  script_tag(name:"affected", value:"Python prior to version 3.7.16, 3.8.x prior to 3.8.16,
  3.9.x prior to 3.9.16 and 3.10.x prior to 3.10.8.");

  script_tag(name:"solution", value:"Update to version 3.7.16, 3.8.16, 3.9.16, 3.10.8, 3.11
  or later.");

  script_xref(name:"URL", value:"https://bugs.python.org/issue24778");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/68966");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/68966#issuecomment-1326478972");
  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/mailcap-shell-injection.html");
  script_xref(name:"Advisory-ID", value:"bpo-24778");

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

if (version_is_less(version: version, test_version: "3.7.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.8.0", test_version_up: "3.8.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.9.0", test_version_up: "3.9.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.10.0", test_version_up: "3.10.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.10.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
