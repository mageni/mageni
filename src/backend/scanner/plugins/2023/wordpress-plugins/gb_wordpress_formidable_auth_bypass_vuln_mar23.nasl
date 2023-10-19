# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:strategy11:formidable_form_builder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126296");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-05-05 13:22:41 +0000 (Fri, 05 May 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-31 13:39:00 +0000 (Fri, 31 Mar 2023)");

  script_cve_id("CVE-2023-0816");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Formidable Forms Builder Plugin < 6.1 Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/formidable/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Formidable Forms Builder' is prone to an
  authentiaction bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin uses several potentially untrusted headers to
  determine the IP address of the client, leading to IP Address spoofing and bypass of anti-spam
  protections.");

  script_tag(name:"affected", value:"WordPress Formidable Forms Builder prior to version 6.1.");

  script_tag(name:"solution", value:"Update to version 6.1 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/a281f63f-e295-4666-8a08-01b23cd5a744");

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

if (version_is_less(version: version, test_version: "6.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
