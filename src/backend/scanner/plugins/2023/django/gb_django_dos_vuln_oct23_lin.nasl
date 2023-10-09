# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151100");
  script_version("2023-10-06T05:06:29+0000");
  script_tag(name:"last_modification", value:"2023-10-06 05:06:29 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-05 03:20:40 +0000 (Thu, 05 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2023-43665");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django < 3.2.22, 4.1.x < 4.1.12, 4.2.x < 4.2.6 DoS Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  script_tag(name:"summary", value:"Django is prone to a denial of service (DoS) vulnerability in
  django.utils.text.Truncator.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Following the fix for CVE-2019-14232, the regular expressions
  used in the implementation of django.utils.text.Truncator's chars() and words() methods (with
  html=True) were revised and improved. However, these regular expressions still exhibited linear
  backtracking complexity, so when given a very long, potentially malformed HTML input, the
  evaluation would still be slow, leading to a potential denial of service vulnerability.");

  script_tag(name:"affected", value:"Django prior to version 3.2.22, version 4.1.x prior through
  4.1.11 and 4.2.x through 4.2.5.");

  script_tag(name:"solution", value:"Update to version 3.2.22, 4.1.12, 4.2.6 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2023/oct/04/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.2.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.22", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.1.0", test_version_up: "4.1.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.12", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.2.0", test_version_up: "4.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.6", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
