# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:aioseo:all_in_one_seo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126368");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-02-28 08:03:57 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-04 03:07:00 +0000 (Sat, 04 Mar 2023)");

  script_cve_id("CVE-2023-0585", "CVE-2023-0586");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress All in One SEO Pack Plugin < 4.3.0 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/all-in-one-seo-pack/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'All in One SEO Pack' is prone to multiple
  stored cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-0585: Authenticated attacker with administrator role or above is able to inject
  arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

  - CVE-2023-0586: Authenticated attacker with contributor role or above is able to inject
  arbitrary web scripts in pages that will execute whenever a user accesses an injected page.");

  script_tag(name:"affected", value:"WordPress All in One SEO Pack plugin prior to version
  4.3.0.");

  script_tag(name:"solution", value:"Update to version 4.3.0 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/all-in-one-seo-pack/all-in-one-seo-pack-429-authenticated-administrator-stored-cross-site-scripting");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/all-in-one-seo-pack/all-in-one-seo-pack-429-authenticated-contributor-stored-cross-site-scripting");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: FALSE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.0", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
