# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:chamilo:chamilo_lms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127208");
  script_version("2023-06-01T09:09:48+0000");
  script_tag(name:"last_modification", value:"2023-06-01 09:09:48 +0000 (Thu, 01 Jun 2023)");
  # nb: This was initially a single VT but got split later into multiple due to different affected /
  # fixed versions. Thus the original creation_date of the first VT has been kept.
  script_tag(name:"creation_date", value:"2022-09-30 08:47:25 +0000 (Fri, 30 Sep 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2022-40407");

  # nb: Seems no actual "patch" has been provided and the user needs to apply some mitigations
  # manually which is something we can't detect.
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Chamilo LMS 'CVE-2022-40407' RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_chamilo_http_detect.nasl");
  script_mandatory_keys("chamilo/detected");

  script_tag(name:"summary", value:"Chamilo LMS is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker could execute authenticated RCE via malicious zip
  file upload.");

  script_tag(name:"affected", value:"Chamilo LMS in all versions without applied migitations.");

  script_tag(name:"solution", value:"Please see the referenced advisory how to mitigate this
  vulnerability.");

  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-94-2022-09-06-High-impact-Moderate-risk-Authenticated-RCE-via-zipslip-attack-in-file-upload-CVE-2022-40407");

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

report = report_fixed_ver(installed_version: version, fixed_version: "See vendor advisory", install_path: location);
security_message(port: port, data: report);
exit(0);
