# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832713");
  script_version("2023-12-01T05:05:39+0000");
  script_cve_id("CVE-2023-6204", "CVE-2023-6205", "CVE-2023-6206", "CVE-2023-6207",
                "CVE-2023-6209", "CVE-2023-6210", "CVE-2023-6211", "CVE-2023-6212",
                "CVE-2023-6213");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-12-01 05:05:39 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-28 19:29:00 +0000 (Tue, 28 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-23 11:11:10 +0530 (Thu, 23 Nov 2023)");
  script_name("Mozilla Firefox Security Update (mfsa_2023-49_2023-52) - MAC OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Out-of-bound memory access in WebGL2 blitFramebuffer.

  - Use-after-free in MessagePort::Entangled.

  - Clickjacking permission prompts using the fullscreen transition.

  - Use-after-free in ReadableByteStreamQueueEntry::Buffer.

  - Incorrect parsing of relative URLs.

  - Mixed-content resources not blocked in a javascript: pop-up.

  - Clickjacking to load insecure pages in HTTPS-only mode.

  - Multiple Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and memory leak and corruption and cause denial
  of service on an affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  120 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to version 120 or later,
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-49/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"120")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"120", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}
