# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:spip:spip";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170331");
  script_version("2023-03-31T10:08:38+0000");
  script_tag(name:"last_modification", value:"2023-03-31 10:08:38 +0000 (Fri, 31 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-02 13:24:03 +0000 (Thu, 02 Mar 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2023-27372");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SPIP 3.2.x < 3.2.18, 4.x < 4.0.10, 4.1.x < 4.1.8, 4.2.x < 4.2.1 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_spip_http_detect.nasl");
  script_mandatory_keys("spip/detected");

  script_tag(name:"summary", value:"SPIP is prone to a remote command execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SPIP allows remote code execution via form values in the public
  area because serialization is mishandled.");

  script_tag(name:"affected", value:"SPIP version 3.2.x prior to 3.2.18, 4.x prior to 4.0.10, 4.1.x
  prior to 4.1.8 and 4.2.x prior to 4.2.1.");

  script_tag(name:"solution", value:"Update to version 3.2.18, 4.0.10, 4.1.8, 4.2.1 or later.");

  script_xref(name:"URL", value:"https://blog.spip.net/Mise-a-jour-critique-de-securite-sortie-de-SPIP-4-2-1-SPIP-4-1-8-SPIP-4-0-10-et.html?lang=fr");
  script_xref(name:"URL", value:"https://git.spip.net/spip/spip/commit/5aedf49b89415a4df3eb775eee3801a2b4b88266");
  script_xref(name:"URL", value:"https://git.spip.net/spip/spip/commit/96fbeb38711c6706e62457f2b732a652a04a409d");

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

if (version_in_range_exclusive(version: version, test_version_lo: "3.2.0", test_version_up: "3.2.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.0.0", test_version_up: "4.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.1.0", test_version_up: "4.1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.2.0", test_version_up: "4.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
