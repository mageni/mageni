# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:incsub:forminator";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124480");
  script_version("2023-11-30T05:06:26+0000");
  script_tag(name:"last_modification", value:"2023-11-30 05:06:26 +0000 (Thu, 30 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-21 07:31:23 +0000 (Tue, 21 Nov 2023)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-27 16:33:00 +0000 (Mon, 27 Nov 2023)");

  script_cve_id("CVE-2023-5119");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Forminator Plugin < 1.27.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/forminator/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Forminator' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not properly sanitize the redirect-url field
  in the form submission settings, which could allow high-privilege users such as an administrator
  to inject arbitrary web scripts even when the unfiltered_html capability is disallowed.");

  script_tag(name:"affected", value:"WordPress Forminator plugin prior to version 1.27.0.");

  script_tag(name:"solution", value:"Update to version 1.27.0 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/229207bb-8f8d-4579-a8e2-54516474ccb4/");

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

if (version_is_less(version: version, test_version: "1.27.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.27.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
