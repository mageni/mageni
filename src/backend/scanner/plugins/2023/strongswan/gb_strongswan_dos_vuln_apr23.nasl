# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:strongswan:strongswan";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126151");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-04-18 11:48:43 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-25 15:36:00 +0000 (Tue, 25 Apr 2023)");

  script_cve_id("CVE-2023-26463");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("strongSwan 5.9.8 < 5.9.10 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_strongswan_ssh_login_detect.nasl");
  script_mandatory_keys("strongswan/detected");

  script_tag(name:"summary", value:"strongSwan is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Related to certificate verification in TLS-based EAP methods
  was discovered in strongSwan that results in a denial of service but possibly even remote code
  execution.");

  script_tag(name:"affected", value:"strongSwan version 5.9.8 prior to 5.9.10.");

  script_tag(name:"solution", value:"Update to version 5.9.10 or later.");

  script_xref(name:"URL", value:"https://www.strongswan.org/blog/2023/03/02/strongswan-vulnerability-%28cve-2023-26463%29.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "5.9.8", test_version_up: "5.9.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.9.10", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
