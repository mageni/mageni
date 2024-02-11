# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832808");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2024-0741", "CVE-2024-0742", "CVE-2024-0747", "CVE-2024-0749",
                "CVE-2024-0750", "CVE-2024-0751", "CVE-2024-0753", "CVE-2024-0755");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-29 22:47:49 +0000 (Mon, 29 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-01-24 17:35:43 +0530 (Wed, 24 Jan 2024)");
  script_name("Mozilla Thunderbird Security Update (mfsa_2024-01_2024-04) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Out of bounds write in ANGLE.

  - Failure to update user input timestamp.

  - Bypass of Content Security Policy when directive unsafe-inline was set.

  - Phishing site popup could show local origin in address bar.

  - Potential permissions request bypass via clickjacking.

  - Privilege escalation through devtools.

  - HSTS policy on subdomain could bypass policy of upper domain.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions and gain
  privilege escalation on an affected system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird versions before
  115.7 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to version 115.7 or later,
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-04/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"115.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"115.7", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
