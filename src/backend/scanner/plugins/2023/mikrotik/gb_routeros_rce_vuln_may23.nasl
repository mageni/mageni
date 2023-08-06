# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150776");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-27 03:36:39 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-32154");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Only with rare specific settings

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS < 6.48.7, 6.49.x < 6.49.8, 7.x < 7.9.1 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a remote code execution (RCE)
  vulnerability in the IPv6 advertisement receiver functionality.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"This vulnerability allows network-adjacent attackers to execute
  arbitrary code on affected installations of Mikrotik RouterOS. Authentication is not required to
  exploit this vulnerability.");

  script_tag(name:"affected", value:"MikroTik RouterOS prior to version 6.48.7, version 6.49.x
  prior to 6.49.8 and 7.x prior to 7.9.1 with enabled IPv6 advertisement receiver functionality.");

  script_tag(name:"solution", value:"Update to version 6.48.7, 6.49.8, 7.9.1 or later.

  Please see the referenced vendor advisory for mitigation steps.");

  script_xref(name:"URL", value:"https://blog.mikrotik.com/security/cve-2023-32154.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.48.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.48.7");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.49.0", test_version_up: "6.49.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.49.8");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.9.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.9.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
