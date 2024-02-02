# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ilias:ilias";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126680");
  script_version("2024-01-23T05:05:19+0000");
  script_tag(name:"last_modification", value:"2024-01-23 05:05:19 +0000 (Tue, 23 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-22 10:32:02 +0000 (Mon, 22 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ILIAS < 8.8 Broken Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ilias_http_detect.nasl");
  script_mandatory_keys("ilias/detected");

  script_tag(name:"summary", value:"ILIAS is prone to a broken access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"WAC can be used to circumvent access restrictions
  (offscript).");

  script_tag(name:"affected", value:"ILIAS prior to version 8.8.");

  script_tag(name:"solution", value:"Update to version 8.8 or later.");

  script_xref(name:"URL", value:"https://docu.ilias.de/ilias.php?baseClass=illmpresentationgui&cmd=layout&ref_id=35&obj_id=154885");

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

if (version_is_less(version: version, test_version: "8.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
