# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zoom:zoom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149920");
  script_version("2023-07-13T05:06:09+0000");
  script_tag(name:"last_modification", value:"2023-07-13 05:06:09 +0000 (Thu, 13 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-12 03:50:35 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");

  script_cve_id("CVE-2023-34116");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zoom Client < 5.15.0 Privilege Escalation Vulnerability (ZSB-23018) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_zoom_client_smb_login_detect.nasl");
  script_mandatory_keys("zoom/client/win/detected");

  script_tag(name:"summary", value:"Zoom Client is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improper input validation in the Zoom Desktop Client for
  Windows may allow an unauthorized user to enable an escalation of privilege via network access.");

  script_tag(name:"affected", value:"Zoom Client prior to version 5.15.0.");

  script_tag(name:"solution", value:"Update to version 5.15.0 or later.");

  script_xref(name:"URL", value:"https://explore.zoom.us/en/trust/security/security-bulletin/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.15.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.15.0", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
