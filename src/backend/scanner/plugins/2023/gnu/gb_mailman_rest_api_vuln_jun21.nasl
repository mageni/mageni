# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gnu:mailman";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149574");
  script_version("2023-04-21T06:51:15+0000");
  script_tag(name:"last_modification", value:"2023-04-21 06:51:15 +0000 (Fri, 21 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-21 06:48:15 +0000 (Fri, 21 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2021-34337");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mailman < 3.3.5 REST API Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("mailman_detect.nasl");
  script_mandatory_keys("gnu_mailman/detected");

  script_tag(name:"summary", value:"Mailman is prone to a vulnerability in the REST API.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker with access to the REST API could use timing
  attacks to determine the value of the configured REST API password and then make arbitrary REST
  API calls. The REST API is bound to localhost by default, limiting the ability for attackers to
  exploit this, but can optionally be made to listen on other interfaces.");

  script_tag(name:"affected", value:"Mailman prior to version 3.3.5.");

  script_tag(name:"solution", value:"Update to version 3.3.5 or later.");

  script_xref(name:"URL", value:"https://gitlab.com/mailman/mailman/-/commit/e4a39488c4510fcad8851217f10e7337a196bb51");

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

if (version_is_less(version: version, test_version: "3.3.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
