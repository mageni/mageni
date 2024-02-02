# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zoom:zoom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150990");
  script_version("2023-11-22T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-11-22 05:05:24 +0000 (Wed, 22 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-09-15 05:46:01 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-15 19:11:00 +0000 (Fri, 15 Sep 2023)");

  script_cve_id("CVE-2023-39204", "CVE-2023-39208");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zoom Client < 5.15.10 Multiple Vulnerabilities (ZSB-23043, ZSB-23048) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_zoom_client_ssh_login_linux_detect.nasl");
  script_mandatory_keys("zoom/client/lin/detected");

  script_tag(name:"summary", value:"The Zoom Client is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-39204 / ZSB-23048: Buffer overflow in some Zoom clients may allow an unauthenticated
  user to conduct a denial of service via network access.

  - CVE-2023-39208 / ZSB-23043: Improper input validation in Zoom Desktop Client for Linux may
  allow an unauthenticated user to conduct a denial of service via network access.");

  script_tag(name:"affected", value:"Zoom Client prior to version 5.15.10.");

  script_tag(name:"solution", value:"Update to version 5.15.10 or later.");

  script_xref(name:"URL", value:"https://explore.zoom.us/en/trust/security/security-bulletin/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.15.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.15.10", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
