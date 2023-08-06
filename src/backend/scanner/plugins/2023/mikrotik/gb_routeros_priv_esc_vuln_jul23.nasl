# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150774");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-27 03:07:31 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2023-30799");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS < 6.49.8 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A remote and authenticated attacker can escalate privileges
  from admin to super-admin on the Winbox or HTTP interface. The attacker can abuse this
  vulnerability to execute arbitrary code on the system.");

  script_tag(name:"affected", value:"MikroTik RouterOS prior to version 6.49.8.");

  script_tag(name:"solution", value:"Update to version 6.49.8 or later.");

  script_xref(name:"URL", value:"https://vulncheck.com/advisories/mikrotik-foisted");
  script_xref(name:"URL", value:"https://vulncheck.com/blog/mikrotik-foisted-revisited");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.49.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.49.8");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
