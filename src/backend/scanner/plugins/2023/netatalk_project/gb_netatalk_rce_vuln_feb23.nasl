# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:netatalk_project:netatalk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149478");
  script_version("2023-04-03T10:10:12+0000");
  script_tag(name:"last_modification", value:"2023-04-03 10:10:12 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-03 03:58:13 +0000 (Mon, 03 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2022-43634");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Netatalk <= 3.1.14 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_netatalk_asip_afp_detect.nasl");
  script_mandatory_keys("netatalk/detected");

  script_tag(name:"summary", value:"Netatalk is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The specific flaw exists within the dsi_writeinit function. The
  issue results from the lack of proper validation of the length of user-supplied data prior to
  copying it to a fixed-length heap-based buffer. An attacker can leverage this vulnerability to
  execute code in the context of root.");

  script_tag(name:"impact", value:"This vulnerability allows remote attackers to execute arbitrary
  code on affected installations of Netatalk. Authentication is not required to exploit this
  vulnerability.");

  script_tag(name:"affected", value:"Netatalk version 3.1.14 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 03rd April, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-094/");
  script_xref(name:"URL", value:"https://github.com/Netatalk/Netatalk/pull/186");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "3.1.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
