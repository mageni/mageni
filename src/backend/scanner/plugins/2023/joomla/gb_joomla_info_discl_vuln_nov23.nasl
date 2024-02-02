# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151328");
  script_version("2023-12-08T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-12-08 05:05:53 +0000 (Fri, 08 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-30 03:05:48 +0000 (Thu, 30 Nov 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-05 15:52:00 +0000 (Tue, 05 Dec 2023)");

  script_cve_id("CVE-2023-40626");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! 1.6.0 - 4.4.0, 5.0.0 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The language file parsing process could be manipulated to
  expose environment variables. Environment variables might contain sensible information.");

  script_tag(name:"affected", value:"Joomla! version 1.6.0 through 4.4.0 and version 5.0.0.");

  script_tag(name:"solution", value:"Update to version 4.4.1, 5.0.1 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/919-20231101-core-exposure-of-environment-variables.html");

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

if (version_in_range(version: version, test_version: "1.6.0", test_version2: "4.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
