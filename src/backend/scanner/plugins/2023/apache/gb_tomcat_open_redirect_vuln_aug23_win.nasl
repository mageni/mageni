# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150909");
  script_version("2023-08-29T05:06:28+0000");
  script_tag(name:"last_modification", value:"2023-08-29 05:06:28 +0000 (Tue, 29 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-28 03:20:06 +0000 (Mon, 28 Aug 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2023-41080");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Open Redirect Vulnerability (Aug 2023) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to an open redirect vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If the ROOT (default) web application is configured to use FORM
  authentication then it is possible that a specially crafted URL could be used to trigger a
  redirect to an URL of the attackers choice.");

  script_tag(name:"affected", value:"Apache Tomcat versions 8.5.0 through 8.5.92, 9.0.0-M1 through
  9.0.79, 10.1.0-M1 through 10.1.12 and 11.0.0-M1 through 11.0.0-M10.");

  script_tag(name:"solution", value:"Update to version 8.5.93, 9.0.80, 10.1.13, 11.0.0-M11 or
  later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/71wvwprtx2j2m54fovq9zr7gbm2wow2f");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.0-M11");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.13");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.80");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.93");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.5.0", test_version_up: "8.5.93")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.93", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0.0.M1", test_version_up: "9.0.80")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.80", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.1.0.M1", test_version_up: "11.0.0.M11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.0-M11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0.M1", test_version_up: "11.0.0.M11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.0-M11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
