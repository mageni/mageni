# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:intuitive_custom_post_order_project:intuitive_custom_post_order";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126428");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-07-12 12:08:03 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-28 02:22:00 +0000 (Tue, 28 Feb 2023)");

  script_cve_id("CVE-2022-4385", "CVE-2022-4386");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Intuitive Custom Post Order Plugin < 3.1.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/intuitive-custom-post-order/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Intuitive Custom Post Order' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-4385: The plugin does not check for authorization in the update-menu-order ajax action
  allowing any logged in user, with roles as low as Subscriber to update the menu order.

  - CVE-2023-4386: The plugin lacks CSRF protection in its update-menu-order ajax action, allowing
  an attacker to trick any user to change the menu order via a CSRF attack.");

  script_tag(name:"affected", value:"WordPress Intuitive Custom Post Order plugin prior to
  version 3.1.4.");

  script_tag(name:"solution", value:"Update to version 3.1.4 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/8f900d37-6eee-4434-8b9b-d10cc4a9167c");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/734064e3-afe9-4dfd-8d76-8a757cc94815");

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

if (version_is_less(version: version, test_version: "3.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
