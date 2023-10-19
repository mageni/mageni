# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170599");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-11 08:05:57 +0000 (Wed, 11 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-16 14:00:00 +0000 (Mon, 16 Oct 2023)");

  script_cve_id("CVE-2023-42794");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat DoS Vulnerability (Oct 2023) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Tomcat's internal fork of a Commons FileUpload included an
  unreleased, in progress refactoring that exposed a potential denial of service on Windows if a web
  application opened a stream for an uploaded file but  failed to close the stream. The file would
  never be deleted from disk creating the possibility of an eventual denial of service due to the disk
  being full.");

  script_tag(name:"affected", value:"Apache Tomcat versions 8.5.85 through 8.5.93 and 9.0.70 through
  9.0.80 on Windows only.");

  script_tag(name:"solution", value:"Update to version 8.5.94, 9.0.81 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/vvbr2ms7lockj1hlhz5q3wmxb2mwcw82");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.81");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.94");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "8.5.85", test_version_up: "8.5.94")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.94", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0.70", test_version_up: "9.0.81")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.81", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
