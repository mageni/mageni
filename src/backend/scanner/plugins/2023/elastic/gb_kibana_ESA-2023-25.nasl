# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126535");
  script_version("2023-12-20T12:22:41+0000");
  script_tag(name:"last_modification", value:"2023-12-20 12:22:41 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-16 08:53:44 +0000 (Thu, 16 Nov 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-18 18:01:00 +0000 (Mon, 18 Dec 2023)");

  script_cve_id("CVE-2023-46671");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana 8.0.x < 8.11.1 Information Disclosure Vulnerability (ESA-2023-25)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_detect_http.nasl");
  script_mandatory_keys("elastic/kibana/detected");

  script_tag(name:"summary", value:"Kibana is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If an error occurred, sensitive information was recorded in the
  event of an error. The error message recorded in the log may contain account credentials for
  the kibana_system user, API Keys, and credentials of Kibana end-users.");

  script_tag(name:"affected", value:"Kibana versions 8.0.x prior to 8.11.1.");

  script_tag(name:"solution", value:"Update to version 8.11.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/kibana-8-11-1-security-update-esa-2023-25/347149");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.0.0", test_version_up: "8.11.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.11.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
