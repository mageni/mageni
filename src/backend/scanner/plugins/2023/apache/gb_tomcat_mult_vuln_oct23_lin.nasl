# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170597");
  script_version("2023-10-17T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-11 08:05:57 +0000 (Wed, 11 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-14 01:15:00 +0000 (Sat, 14 Oct 2023)");

  script_cve_id("CVE-2023-42795", "CVE-2023-44487", "CVE-2023-45648");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Multiple Vulnerabilities (Oct 2023) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Tomcat is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-42795: When recycling various internal objects, including the request and the response,
  prior to re-use by the next request/response, an error could cause Tomcat to skip some parts of the
  recycling process leading to information leaking from the current request/response to the next.

  - CVE-2023-44487: HTTP/2 rapid reset attack

  - CVE-2023-45648: A specially crafted, invalid trailer header could cause Tomcat to treat a single
  request as multiple requests leading to the possibility of request smuggling when behind a reverse
  proxy.");

  script_tag(name:"affected", value:"Apache Tomcat versions 8.5.0 through 8.5.93, 9.0.0-M1 through
  9.0.80, 10.0.0 through 10.1.13 and 11.0.0-M1 through 11.0.0-M11.");

  script_tag(name:"solution", value:"Update to version 8.5.94, 9.0.81, 10.1.14, 11.0.0-M12 or
  later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/065jfyo583490r9j2v73nhpyxdob56lw");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/3m81kt8c2gtg4nkjfwt2hvt5l9ycx6vl");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/2pv8yz1pyp088tsxfb7ogltk9msk0jdp");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.0-M12");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.14");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.81");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.94");
  script_xref(name:"URL", value:"https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack");
  script_xref(name:"URL", value:"https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/");
  script_xref(name:"URL", value:"https://aws.amazon.com/blogs/security/how-aws-protects-customers-from-ddos-events/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/10/10/6");
  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.5.0", test_version_up: "8.5.94")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.94", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0.0.M1", test_version_up: "9.0.81")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.81", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0.0", test_version_up: "10.1.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0.M1", test_version_up: "11.0.0.M12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.0-M12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
