# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tawk:tawk.to_live_chat";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126482");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-15 11:30:35 +0000 (Tue, 15 Aug 2023)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-06 21:08:00 +0000 (Mon, 06 Dec 2021)");

  script_cve_id("CVE-2021-24914");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Tawk.To Live Chat Plugin < 0.6.0 Broken Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/tawkto-live-chat/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Tawk.To Live Chat' is prone to a broken
  access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The plugin does not have capability and CSRF checks in the
  tawkto_setwidget and tawkto_removewidget AJAX actions, available to any authenticated user. The
  first one allows low-privileged users to change the some tawkto parameters. The second one will
  remove the live chat widget from pages.");

  script_tag(name:"affected", value:"WordPress Tawk.To Live Chat plugin prior to version 0.6.0.");

  script_tag(name:"solution", value:"Update to version 0.6.0 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/39392055-8cd3-452f-8bcb-a650f5bddc2e");

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

if (version_is_less(version: version, test_version: "0.6.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.6.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
