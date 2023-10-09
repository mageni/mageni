# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zoom:zoom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118522");
  script_version("2023-08-16T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-08-16 05:05:28 +0000 (Wed, 16 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-09 14:39:14 +0000 (Wed, 09 Aug 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");

  script_cve_id("CVE-2023-36534", "CVE-2023-39216");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zoom Client < 5.14.7 Multiple Privilege Escalation Vulnerabilities (ZSB-23030, ZSB-23032) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_zoom_client_smb_login_detect.nasl");
  script_mandatory_keys("zoom/client/win/detected");

  script_tag(name:"summary", value:"Zoom Client is prone to multiple privilege escalation
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-36534: A Path traversal may allow an unauthenticated user to enable an escalation of
  privilege via network access (ZSB-23030).

  - CVE-2023-39216: An improper input validation may allow an unauthenticated user to enable an
  escalation of privilege via network access (ZSB-23032).");

  script_tag(name:"affected", value:"Zoom Client prior to version 5.14.7.");

  script_tag(name:"solution", value:"Update to version 5.14.7 or later.");

  script_xref(name:"URL", value:"https://explore.zoom.us/en/trust/security/security-bulletin/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.14.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.14.7", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
