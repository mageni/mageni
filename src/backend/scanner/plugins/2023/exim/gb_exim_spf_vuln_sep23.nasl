# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:exim:exim";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151116");
  script_version("2023-10-17T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  # nb: This was initially a single VT but got split later into multiple due to different affected /
  # fixed versions. To avoid wrong stats about CVE coverage the "creation_date" of the original VT
  # has been kept here because all CVEs had been covered at this time.
  script_tag(name:"creation_date", value:"2023-09-29 04:31:53 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-42118");

  script_tag(name:"qod_type", value:"remote_banner"); # TODO: needs to be adjusted once a fix is available

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Exim <= 4.96.2 libspf2 RCE Vulnerability (Sep 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_exim_detect.nasl");
  script_mandatory_keys("exim/installed");

  script_tag(name:"summary", value:"Exim is prone to a remote code execution (RCE) vulnerability
  in libspf2.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The specific flaw exists within the parsing of SPF macros. When
  parsing SPF macros, the process does not properly validate user-supplied data, which can result
  in an integer underflow before writing to memory. An attacker can leverage this vulnerability to
  execute code in the context of the service account.");

  script_tag(name:"solution", value:"No known solution is available as of 16th October, 2023.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.exim.org/static/doc/security/CVE-2023-zdi.txt");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-1472/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "4.96.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
