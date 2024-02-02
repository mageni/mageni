# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832609");
  script_version("2024-01-22T05:07:31+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-23518", "CVE-2023-23517", "CVE-2023-23496", "CVE-2022-0108",
                "CVE-2023-23529");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-01-22 05:07:31 +0000 (Mon, 22 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-08 15:55:00 +0000 (Wed, 08 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-10-27 13:07:18 +0530 (Fri, 27 Oct 2023)");
  script_name("Apple Safari Security Update (HT213638)");

  script_tag(name:"summary", value:"Apple Safari is multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Improper memory handling, state management, checks.

  - Improper iframe sandbox enforcement.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities
  will allow attackers to conduct arbitrary code execution and information disclosure.");

  script_tag(name:"affected", value:"Apple Safari versions before 16614.4.6.11.6 on
  macOS Big Sur and 17614.4.6.11.6 on macOS Monterey.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari 16614.4.6.11.6 on
  macOS Big Sur and 17614.4.6.11.6 on macOS Monterey.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213638");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || (osVer !~ "^12\." && osVer !~ "^11\.") || "Mac OS X" >!< osName)
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

buildVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/Safari.app/Contents/Info CFBundleVersion"));

if(osVer =~ "^11\.") {
  if(version_is_less(version:vers, test_version:"16.3"))
    fix = "Upgrade to 16.3 and install update";

  else if(vers == "16.3") {
    if(version_is_less(version:buildVer, test_version:"16614.4.6.11.6")) {
      fix = "Apply update from vendor";
      vers = vers + " Build " + buildVer;
    }
  }
}

if(osVer =~ "^12\.") {
  if(version_is_less(version:vers, test_version:"16.3"))
    fix = "Upgrade to 16.3 and install update";

  else if(vers == "16.3") {
    if(version_is_less(version:buildVer, test_version:"17614.4.6.11.6")) {
      fix = "Apply update from vendor";
      vers = vers + " Build " + buildVer;
    }
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
