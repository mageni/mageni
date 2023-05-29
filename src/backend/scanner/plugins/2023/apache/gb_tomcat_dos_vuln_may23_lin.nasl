# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104754");
  script_version("2023-05-23T11:14:48+0000");
  script_tag(name:"last_modification", value:"2023-05-23 11:14:48 +0000 (Tue, 23 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-22 12:20:07 +0000 (Mon, 22 May 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  # nb: CVE-2023-24998 was added here because it was insufficiently fixed...
  script_cve_id("CVE-2023-24998", "CVE-2023-28709");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat DoS Vulnerability (May 2023) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The fix for CVE-2023-24998 was incomplete. If non-default HTTP
  connector settings were used such that the maxParameterCount could be reached using query string
  parameters and a request was submitted that supplied exactly maxParameterCount parameters in the
  query string, the limit for uploaded request parts could be bypassed with the potential for a
  denial of service to occur.");

  script_tag(name:"affected", value:"Apache Tomcat versions 8.5.85 through 8.5.87, 9.0.71 through
  9.0.73, 10.1.5 through 10.1.7 and 11.0.0-M2 through 11.0.0-M4.");

  script_tag(name:"solution", value:"Update to version 8.5.88, 9.0.74, 10.1.8, 11.0.0-M5 or
  later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/7wvxonzwb7k9hx9jt3q33cmy7j97jo3j");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.0-M5");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.8");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.74");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.88");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.5.85", test_version_up: "8.5.88")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.88", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0.71", test_version_up: "9.0.74")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.74", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.1.5", test_version_up: "10.1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0.M2", test_version_up: "11.0.0.M5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.0-M5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
