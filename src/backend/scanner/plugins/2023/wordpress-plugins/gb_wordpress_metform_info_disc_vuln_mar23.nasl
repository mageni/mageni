# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpmet:metform_elementor_contact_form_builder";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126000");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-03-02 11:12:39 +0000 (Thu, 02 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-18 14:44:00 +0000 (Wed, 18 May 2022)");

  script_cve_id("CVE-2022-1442");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Metform Elementor Contact Form Builder Plugin < 2.1.4 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/metform/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Metform Elementor Contact Form Builder'
  is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Sensitive information disclosure due to improper access control
  in the /core/forms/action.php.");

  script_tag(name:"affected", value:"WordPress Metform Elementor Contact Form Builder plugin prior
  to version 2.1.4.");

  script_tag(name:"solution", value:"Update to version 2.1.4 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/vulnerability-advisories/#CVE-2022-1442");

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

if (version_is_less(version: version, test_version: "2.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
