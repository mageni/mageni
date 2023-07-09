# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zoom:zoom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149877");
  script_version("2023-07-06T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-06 05:05:36 +0000 (Thu, 06 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-05 04:13:40 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2023-28601", "CVE-2023-34113", "CVE-2023-34114", "CVE-2023-34120",
                "CVE-2023-34121", "CVE-2023-34122");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zoom Client < 5.14.10 Multiple Vulnerabilities (ZSB-23009, ZSB-23012 ZSB-23013, ZSB-23014, ZSB-23015, ZSB-23016) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_zoom_client_smb_login_detect.nasl");
  script_mandatory_keys("zoom/client/win/detected");

  script_tag(name:"summary", value:"Zoom Client is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-28601: Improper restriction of operations within the bounds of a memory buffer

  - CVE-2023-34113: Insufficient verification of data authenticity

  - CVE-2023-34114: Exposure of resource to wrong sphere

  - CVE-2023-34120: Improper privilege management

  - CVE-2023-34121: Improper input validation

  - CVE-2023-34122: Improper input validation");

  script_tag(name:"affected", value:"Zoom Client prior to version 5.14.10.");

  script_tag(name:"solution", value:"Update to version 5.14.10 or later.");

  script_xref(name:"URL", value:"https://explore.zoom.us/en/trust/security/security-bulletin/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.14.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.14.10", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
