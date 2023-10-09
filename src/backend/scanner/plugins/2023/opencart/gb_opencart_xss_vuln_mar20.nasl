# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:opencart:opencart";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126479");
  script_version("2023-09-01T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-09-01 05:05:17 +0000 (Fri, 01 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-08-25 09:03:24 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-03 18:15:00 +0000 (Wed, 03 Jun 2020)");

  script_cve_id("CVE-2020-10596");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenCart < 3.0.3.3 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("opencart_detect.nasl");
  script_mandatory_keys("OpenCart/installed");

  script_tag(name:"summary", value:"OpenCart is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cross-site scripting (XSS) via a crafted filename in the users'
  image upload section.");

  script_tag(name:"affected", value:"OpenCart prior to version 3.0.3.3.");

  script_tag(name:"solution", value:"Update to version 3.0.3.3 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-36fm-v9wv-56jf");

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

if (version_is_less(version: version, test_version: "3.0.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.3.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
