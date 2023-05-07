# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149633");
  script_version("2023-05-04T09:51:03+0000");
  script_tag(name:"last_modification", value:"2023-05-04 09:51:03 +0000 (Thu, 04 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-04 04:59:51 +0000 (Thu, 04 May 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2023-26486");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana 7.9.0 - 7.17.9, 8.0.0 - 8.6.2 XSS Vulnerability (ESA-2023-05)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_detect_http.nasl");
  script_mandatory_keys("elastic/kibana/detected");

  script_tag(name:"summary", value:"Kibana is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in one of Kibana's dependencies, which
  could allow arbitrary JavaScript to be executed in a victim's browser via a maliciously crafted
  custom visualization in Kibana.");

  script_tag(name:"affected", value:"Kibana version 7.9.0 through 7.17.9 and 8.0.0 through 8.6.2.");

  script_tag(name:"solution", value:"Update to version 7.17.10, 8.7.0 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-8-7-0-7-17-10-security-updates/332327");

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

if (version_in_range(version: version, test_version: "7.9.0", test_version2: "7.17.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.17.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.6.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
