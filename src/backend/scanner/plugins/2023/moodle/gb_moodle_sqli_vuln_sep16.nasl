# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126531");
  script_version("2023-10-30T05:05:39+0000");
  script_tag(name:"last_modification", value:"2023-10-30 05:05:39 +0000 (Mon, 30 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-26 16:31:42 +0000 (Thu, 26 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2006-4785");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 1.6.2 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to an sql injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A remote attacker could send specially-crafted SQL statements
  to the blog/edit.php script using the blogEntry parameter, which could allow the attacker to
  view, add, modify or delete information in the back-end database.");

  script_tag(name:"affected", value:"Moodle prior to version 1.6.2.");

  script_tag(name:"solution", value:"Update to version 1.6.2 or later.");

  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/29001");

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

if (version_is_less(version: version, test_version: "1.6.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.6.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
