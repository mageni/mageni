# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagely:nextgen_gallery";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126451");
  script_version("2023-10-13T16:09:03+0000");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-08-09 11:12:39 +0000 (Wed, 09 Aug 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-06 21:03:00 +0000 (Thu, 06 Feb 2020)");

  script_cve_id("CVE-2013-0291");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress NextGEN Gallery Plugin 1.9.10 < 2.0.0 Path Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/nextgen-gallery/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Imagely NextGen Gallery' is prone to a
  path disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"User could obtain information about paths, that he/she is not
  supposed to know in the server.");

  script_tag(name:"affected", value:"WordPress NextGEN Gallery plugin version 1.9.10 prior to
  2.0.0");

  script_tag(name:"solution", value:"Update to version 2.0.0 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/4b7d6b66-f96a-4f54-9982-01885291c216");

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

if (version_in_range_exclusive(version: version, test_version_lo: "1.9.10", test_version_up: "2.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
