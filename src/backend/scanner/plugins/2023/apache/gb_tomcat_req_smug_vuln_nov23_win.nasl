# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151317");
  script_version("2023-12-07T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-12-07 05:05:41 +0000 (Thu, 07 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-29 03:09:34 +0000 (Wed, 29 Nov 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-04 19:11:00 +0000 (Mon, 04 Dec 2023)");

  script_cve_id("CVE-2023-46589");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Request Smuggling Vulnerability (Nov 2023) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a request smuggling vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Tomcat does not correctly parse HTTP trailer headers. A
  specially crafted trailer header that exceeds the header size limit could cause Tomcat to treat a
  single request as multiple requests leading to the possibility of request smuggling when behind a
  reverse proxy.");

  script_tag(name:"affected", value:"Apache Tomcat versions 8.5.0 through 8.5.95, 9.0.0-M1 through
  9.0.82, 10.1.0-M1 through 10.1.15 and 11.0.0-M1 through 11.0.0-M10.");

  script_tag(name:"solution", value:"Update to version 8.5.96, 9.0.83, 10.1.16, 11.0.0-M11 or
  later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/0rqq6ktozqc42ro8hhxdmmdjm1k1tpxr");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.0-M11");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.16");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.83");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.96");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.5.0", test_version_up: "8.5.96")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.96", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0.0.M1", test_version_up: "9.0.83")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.83", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.1.0.M1", test_version_up: "10.1.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0.M1", test_version_up: "11.0.0.M11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.0-M11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
