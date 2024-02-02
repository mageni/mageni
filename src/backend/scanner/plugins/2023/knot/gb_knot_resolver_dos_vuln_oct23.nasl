# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nic:knot_resolver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170618");
  script_version("2023-11-03T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-24 07:12:40 +0000 (Tue, 24 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-01 14:29:00 +0000 (Wed, 01 Nov 2023)");

  script_cve_id("CVE-2023-46317");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Knot Resolver < 5.7.0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_knot_resolver_detect.nasl");
  script_mandatory_keys("knot/resolver/detected");

  script_tag(name:"summary", value:"Knot Resolver is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Knot Resolver performs many TCP reconnections upon receiving
  certain nonsensical responses from servers.");

  script_tag(name:"affected", value:"Knot Resolver prior to version 5.7.0.");

  script_tag(name:"solution", value:"Update to version 5.7.0 or later.");

  script_xref(name:"URL", value:"https://www.knot-resolver.cz/2023-08-22-knot-resolver-5.7.0.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.7.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.7.0", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
