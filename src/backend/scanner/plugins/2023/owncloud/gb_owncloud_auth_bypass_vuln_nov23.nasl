# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124481");
  script_version("2023-12-07T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-12-07 05:05:41 +0000 (Thu, 07 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-22 06:15:17 +0000 (Wed, 22 Nov 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-30 19:28:00 +0000 (Thu, 30 Nov 2023)");

  script_cve_id("CVE-2023-49105");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ownCloud 10.6.x < 10.13.1 Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/detected");

  script_tag(name:"summary", value:"ownCloud is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It is possible to access, modify or delete any file without
  authentication if the username of the victim is known and the victim has no signing-key
  configured (which is the default).");

  script_tag(name:"affected", value:"ownCloud prior to version 10.13.1.");

  script_tag(name:"solution", value:"Update to version 10.13.1 or later.");

  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/webdav-api-authentication-bypass-using-pre-signed-urls/");
  script_xref(name:"URL", value:"https://www.ambionics.io/blog/owncloud-cve-2023-49103-cve-2023-49105");
  script_xref(name:"URL", value:"https://github.com/ambionics/owncloud-exploits");

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

if (version_in_range_exclusive(version: version, test_version_lo: "10.6.0", test_version_up: "10.13.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.13.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
