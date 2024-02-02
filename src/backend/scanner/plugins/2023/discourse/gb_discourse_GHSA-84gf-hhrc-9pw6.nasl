# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170616");
  script_version("2023-10-25T11:49:00+0000");
  script_tag(name:"last_modification", value:"2023-10-25 11:49:00 +0000 (Wed, 25 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-23 10:38:49 +0000 (Mon, 23 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-19 17:55:00 +0000 (Thu, 19 Oct 2023)");

  script_cve_id("CVE-2023-45131");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse 3.1.x <= 3.1.1, 3.2.0.beta1 Unauthorized Access Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to an unauthorized access vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"New chat messages can be read by making an unauthenticated POST
  request to MessageBus.");

  script_tag(name:"affected", value:"Discourse version 3.1.x through 3.1.1 and 3.2.0.beta1.");

  script_tag(name:"solution", value:"Update to version 3.1.2, 3.2.0.beta2 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-84gf-hhrc-9pw6");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/commit/6350ba2cb3366ef5e452c99ccd4eae8be8452a07");

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

if (version_in_range(version: version, test_version: "3.1.0", test_version2: "3.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "3.2.0.beta1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.0.beta2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
