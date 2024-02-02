# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:diskstation_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114304");
  script_version("2024-01-31T14:37:46+0000");
  script_tag(name:"last_modification", value:"2024-01-31 14:37:46 +0000 (Wed, 31 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-24 15:16:43 +0000 (Wed, 24 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-30 17:01:37 +0000 (Tue, 30 Jan 2024)");

  script_cve_id("CVE-2024-0854");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager < 7.2.1-69057-2 Open Redirect Vulnerability (Synology-SA-24:02) - Remote Known Vulnerable Versions Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to an open redirect
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a URL redirection to untrusted site ('Open Redirect')
  vulnerability in the file access component.");

  script_tag(name:"impact", value:"The flaw allows remote authenticated users to conduct phishing
  attacks via unspecified vectors.");

  script_tag(name:"affected", value:"Synology DiskStation Manager prior to version 7.2.1-69057-2.");

  script_tag(name:"solution", value:"Update to firmware version 7.2.1-69057-2 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_24_02");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

# TODO: Advisory still says that "Fixed Release Availability" for DSM 7.1 and 6.2 is "Ongoing" so
# this needs to be cross-checked in the future and if fixes are available added here.

# nb: The patch level version cannot be obtained so when the fix is on a patch level version,
# there will be 2 VTs with different qod_type.

if (revcomp(a: version, b: "7.2.1-69057") < 0) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.1-69057-2");
  security_message(port: 0, data: report);
  exit(0);
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.114305
if (version =~ "^7\.2\.1-69057")
  exit(0);

exit(99);
