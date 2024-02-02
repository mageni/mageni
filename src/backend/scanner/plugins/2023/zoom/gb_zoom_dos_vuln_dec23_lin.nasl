# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zoom:zoom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151453");
  script_version("2023-12-26T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-26 05:05:23 +0000 (Tue, 26 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-21 09:21:49 +0000 (Thu, 21 Dec 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-19 02:03:00 +0000 (Tue, 19 Dec 2023)");

  script_cve_id("CVE-2023-49646");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zoom Client < 5.16.5 DoS Vulnerability (ZSB-23062) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_zoom_client_ssh_login_linux_detect.nasl");
  script_mandatory_keys("zoom/client/lin/detected");

  script_tag(name:"summary", value:"The Zoom Client is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improper authentication may allow an authenticated user to
  conduct a denial of service via network access.");

  script_tag(name:"affected", value:"Zoom Client prior to version 5.16.5.");

  script_tag(name:"solution", value:"Update to version 5.16.5 or later.");

  script_xref(name:"URL", value:"https://www.zoom.com/en/trust/security-bulletin/ZSB-23062/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.16.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.16.5", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
