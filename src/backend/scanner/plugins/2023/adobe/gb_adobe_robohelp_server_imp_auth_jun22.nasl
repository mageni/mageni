# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:robohelp_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126580");
  script_version("2023-11-24T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-11-24 05:05:36 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-20 09:09:13 +0000 (Mon, 20 Nov 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2022-30670");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adobe RoboHelp Server < 11.3 Improper Authorization Vulnerability (APSB22-31)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_robohelp_server_http_detect.nasl", "gb_adobe_robohelp_nd_robohelp_server_smb_login_detect.nasl");
  script_mandatory_keys("adobe/robohelp/server/detected");

  script_tag(name:"summary", value:"Adobe RoboHelp Server is prone to an improper authorization
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"End users with non-administrative privileges could manipulate
  API requests and elevate their account privileges to that of a server administrator.");

  script_tag(name:"affected", value:"Adobe RoboHelp Server prior to version 11.3.");

  script_tag(name:"solution", value:"Update to version 11.3 or later.");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/robohelp-server/apsb22-31.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_is_less(version: vers, test_version: "11.3")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "11.3", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
