# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:qnap:video_station";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151482");
  script_version("2024-01-24T05:06:24+0000");
  script_tag(name:"last_modification", value:"2024-01-24 05:06:24 +0000 (Wed, 24 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-09 03:32:39 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-18 19:56:00 +0000 (Wed, 18 Oct 2023)");

  script_cve_id("CVE-2023-34975", "CVE-2023-34976", "CVE-2023-34977");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Video Station Multiple Vulnerabilities (QSA-23-52)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_videostation_http_detect.nasl");
  script_mandatory_keys("qnap/videostation/detected");

  script_tag(name:"summary", value:"QNAP Video Station is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-34975, CVE-2023-34976: SQL injection (SQLi)

  - CVE-2023-34977: Cross-site scripting (XSS)");

  script_tag(name:"affected", value:"QNAP Video Station versions prior to 5.7.0.");

  script_tag(name:"solution", value:"Update to version 5.7.0 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-23-52");

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

if (version_is_less(version: version, test_version: "5.7.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
