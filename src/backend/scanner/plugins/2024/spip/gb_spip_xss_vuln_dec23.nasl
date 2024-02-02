# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:spip:spip";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151484");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-09 04:17:04 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-10 16:42:00 +0000 (Wed, 10 Jan 2024)");

  script_cve_id("CVE-2023-52322");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SPIP < 4.1.13, 4.2.x < 4.2.7 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_spip_http_detect.nasl");
  script_mandatory_keys("spip/detected");

  script_tag(name:"summary", value:"SPIP is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ecrire/public/assembler.php allows XSS because input from
  _request() is not restricted to safe characters such as alphanumerics.");

  script_tag(name:"affected", value:"SPIP prior to version 4.1.13 and 4.2.x prior to 4.2.7.");

  script_tag(name:"solution", value:"Update to version 4.1.13, 4.2.7 or later.");

  script_xref(name:"URL", value:"https://blog.spip.net/Mise-a-jour-de-maintenance-et-securite-sortie-de-SPIP-4-2-7-SPIP-4-1-13.html?lang=fr");

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

if (version_is_less(version: version, test_version: "4.1.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.2.0", test_version_up: "4.2.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
