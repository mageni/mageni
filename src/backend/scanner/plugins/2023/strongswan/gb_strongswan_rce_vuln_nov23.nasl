# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:strongswan:strongswan";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124488");
  script_version("2023-12-14T08:20:35+0000");
  script_tag(name:"last_modification", value:"2023-12-14 08:20:35 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-08 07:48:43 +0000 (Fri, 08 Dec 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-12 17:07:00 +0000 (Tue, 12 Dec 2023)");

  script_cve_id("CVE-2023-41913");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("strongSwan 5.3.x < 5.9.12 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_strongswan_ssh_login_detect.nasl");
  script_mandatory_keys("strongswan/detected");

  script_tag(name:"summary", value:"strongSwan is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"StrongSwan has a buffer overflow and possible unauthenticated
  remote code execution via a DH public value that exceeds the internal buffer in charon-tkm's DH
  proxy.");

  script_tag(name:"affected", value:"strongSwan version 5.3.x prior to 5.9.12.");

  script_tag(name:"solution", value:"Update to version 5.9.12 or later.");

  script_xref(name:"URL", value:"https://www.strongswan.org/blog/2023/11/20/strongswan-vulnerability-%28cve-2023-41913%29.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "5.3.0", test_version_up: "5.9.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.9.12", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
