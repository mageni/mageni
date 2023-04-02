# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104654");
  script_version("2023-03-24T10:09:03+0000");
  script_tag(name:"last_modification", value:"2023-03-24 10:09:03 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-23 13:02:18 +0000 (Thu, 23 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2023-28708");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Information Disclosure Vulnerability (Mar 2023) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When using the RemoteIpFilter with requests received from a
  reverse proxy via HTTP that include the X-Forwarded-Proto header set to https, session cookies
  created by Tomcat did not include the secure attribute. This could result in the user agent
  transmitting the session cookie over an insecure channel.");

  script_tag(name:"affected", value:"Apache Tomcat versions through 8.5.85, 9.0.0-M1 through 9.0.71,
  10.x through 10.1.5 and 11.0.0-M1 through 11.0.0-M2.");

  script_tag(name:"solution", value:"Update to version 8.5.86, 9.0.72, 10.1.6, 11.0.0-M3 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/hdksc59z3s7tm39x0pp33mtwdrt8qr67");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.0-M3");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.6");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.72");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.86");

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

# nb: Using version_is_less() here on purpose for the similar reason given for 10.0.x below.
if (version_is_less(version: version, test_version: "8.5.86")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.86", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0.0.M1", test_version_up: "9.0.72")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.72", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

# nb: 10.0.x has been used as the lower bound here on purpose vs. 10.1.x as it is unlikely that
# 9.0.0+ and 10.1.0+ was affected but 10.0.x not. More likely the vendor just doesn't mention 10.0.x
# in the advisory anymore because it might be EOL and haven't been evaluated at all or similar...
if (version_in_range_exclusive(version: version, test_version_lo: "10.0", test_version_up: "10.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.1.0.M1", test_version_up: "11.0.0.M3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.0-M3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
