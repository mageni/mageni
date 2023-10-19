# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpfastestcache:wp_fastest_cache";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127465");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-06-07 11:35:51 +0200 (Wed, 07 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-13 13:17:00 +0000 (Thu, 13 Apr 2023)");

  script_cve_id("CVE-2023-1375", "CVE-2023-1918", "CVE-2023-1919", "CVE-2023-1920",
                "CVE-2023-1921", "CVE-2023-1922", "CVE-2023-1923", "CVE-2023-1924",
                "CVE-2023-1925", "CVE-2023-1926", "CVE-2023-1927", "CVE-2023-1928",
                "CVE-2023-1929", "CVE-2023-1930", "CVE-2023-1931");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Fastest Cache Plugin < 1.1.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-fastest-cache/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Fastest Cache' is prone to multiple
  vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnberabilities exist:

  - CVE-2023-1375: There is a missing authorization in 'deleteCacheToolbar'.

  - CVE-2023-1918: There is a cross-site request forgery (CSRF) in 'wpfc_preload_single_callback'
  due to missing or incorrect validation.

  - CVE-2023-1919: There is a cross-site request forgery (CSRF) in
  'wpfc_preload_single_save_settings_callback' due to missing or incorrect validation.

  - CVE-2023-1920: There is a cross-site request forgery (CSRF) in
  'wpfc_purgecache_varnish_callback' due to missing or incorrect validation.

  - CVE-2023-1921: There is a cross-site request forgery (CSRF) in
  'wpfc_start_cdn_integration_ajax_request_callback' due to missing or incorrect validation.

  - CVE-2023-1922: There is a cross-site request forgery (CSRF) in
  'wpfc_pause_cdn_integration_ajax_request_callback' due to missing or incorrect validation.

  - CVE-2023-1923: There is a cross-site request forgery (CSRF) in
  'wpfc_remove_cdn_integration_ajax_request_callback' due to missing or incorrect validation.

  - CVE-2023-1924: There is a cross-site request forgery (CSRF) in
  'wpfc_toolbar_save_settings_callback' due to missing or incorrect validation.

  - CVE-2023-1925: There is a cross-site request forgery (CSRF) in
  'wpfc_clear_cache_of_allsites_callback' due to missing or incorrect validation.

  - CVE-2023-1926: There is a cross-site request forgery (CSRF) in 'deleteCacheToolbar' due to
  missing or incorrect validation.

  - CVE-2023-1927: There is a cross-site request forgery (CSRF) in 'deleteCssAndJsCacheToolbar' due
  to missing or incorrect validation.

  - CVE-2023-1928: There is a missing authorization in 'wpfc_preload_single_callback'.

  - CVE-2023-1929: There is a missing authorization in 'wpfc_purgecache_varnish_callback'.

  - CVE-2023-1930: There is a missing authorization in 'wpfc_clear_cache_of_allsites_callback'.

  - CVE-2023-1931: There is a missing authorization in 'deleteCssAndJsCacheToolbar'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Fastest Cache plugin prior to version 1.1.3.");

  script_tag(name:"solution", value:"Update to version 1.1.3 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/ae643666-70cb-4eb4-a183-e1649264ded4");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/1c8034ff-cf36-498f-9efc-a4e6bbb92b2c");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/024f4058-065b-48b4-a08a-d9732d4375cd");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/c8e90994-3b5c-4ae6-a27f-890a9101b440");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/17c7c61d-c110-448e-ad8a-bc1c00393524");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/a1743b26-861e-4a61-80de-b8cc82308228");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/49ba5cfa-c2cc-49ac-b22d-7e36ccca6ac5");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/a87f610a-c1ef-4365-bd74-569989587d41");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/096257a4-6ee9-41e1-8a59-4ffcd309f83c");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/b793a4cb-3130-428e-9b61-8ce29fcdaf70");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/4d3858f5-3f13-400c-acf4-eb3dc3a43308");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/56a90042-a6c0-4487-811b-ced23c97f9f4");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/1e567aec-07e5-494a-936d-93b40d3e3043");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/bae67a68-4bd1-4b52-b3dd-af0eef014028");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/b4bb2d72-ff31-4220-acb3-ed17bb9229b5");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.1.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.1.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
