# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150998");
  script_version("2023-09-19T05:06:03+0000");
  script_tag(name:"last_modification", value:"2023-09-19 05:06:03 +0000 (Tue, 19 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-18 04:31:43 +0000 (Mon, 18 Sep 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2023-30800");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS 6.0.0 < 6.48.8, 6.49.x < 6.49.10 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The web server used by MikroTik RouterOS is affected by a heap
  memory corruption issue. A remote and unauthenticated attacker can corrupt the server's heap
  memory by sending a crafted HTTP request. As a result, the web interface crashes and is
  immediately restarted.");

  script_tag(name:"affected", value:"MikroTik RouterOS version 6.0.0 through 6.48.7 and 6.49.x
  through 6.49.9.");

  script_tag(name:"solution", value:"Update to version 6.48.8, 6.49.10 or later.");

  script_xref(name:"URL", value:"https://vulncheck.com/advisories/mikrotik-jsproxy-dos");
  script_xref(name:"URL", value:"https://gist.github.com/j-baines/fdd1e85482838c6299900c1e859071c2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "6.0.0", test_version_up: "6.48.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.48.8");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.49.0", test_version_up: "6.49.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.49.10");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
