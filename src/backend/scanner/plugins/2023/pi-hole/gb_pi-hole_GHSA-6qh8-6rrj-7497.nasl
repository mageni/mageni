# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pi-hole:web_interface";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114203");
  script_version("2023-12-01T16:11:30+0000");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-01 06:27:04 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-30 21:50:00 +0000 (Fri, 30 Dec 2022)");

  script_cve_id("CVE-2022-23513");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pi-hole Web Interface 2.0 <= 5.17 Broken Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pi-hole_http_detect.nasl");
  script_mandatory_keys("pi-hole/detected");

  script_tag(name:"summary", value:"The Pi-hole Web Interface (previously AdminLTE) is prone to a
  broken access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In case of an attack, the threat actor will obtain the ability
  to perform an unauthorized query for blocked domains on 'queryads' endpoint. In the case of
  application, this vulnerability exists because of a lack of validation in code on a root server
  path: '/admin/scripts/pi-hole/phpqueryads.php.'");

  script_tag(name:"impact", value:"Potential threat actor(s) are able to perform an unauthorized
  query search in blocked domain lists. This could lead to the disclosure for any victims' personal
  blacklists.");

  script_tag(name:"affected", value:"Pi-hole Web Interface (previously AdminLTE) versions starting
  from 2.0 and through 5.17.");

  script_tag(name:"solution", value:"Update to version 5.18 or later.");

  script_xref(name:"URL", value:"https://github.com/pi-hole/web/security/advisories/GHSA-6qh8-6rrj-7497");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/174460/AdminLTE-PiHole-Broken-Access-Control.html");

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

if (version_in_range(version: version, test_version: "2.0", test_version2: "5.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
