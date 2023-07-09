# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2023.22");
  script_cve_id("CVE-2023-3482", "CVE-2023-37201", "CVE-2023-37202", "CVE-2023-37203", "CVE-2023-37204", "CVE-2023-37205", "CVE-2023-37206", "CVE-2023-37207", "CVE-2023-37208", "CVE-2023-37209", "CVE-2023-37210", "CVE-2023-37211", "CVE-2023-37212");
  script_tag(name:"creation_date", value:"2023-07-05 06:27:18 +0000 (Wed, 05 Jul 2023)");
  script_version("2023-07-06T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-06 05:05:36 +0000 (Thu, 06 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mozilla Firefox Security Advisory (MFSA2023-22) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2023-22");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-22/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1750870%2C1825552%2C1826206%2C1827076%2C1828690%2C1833503%2C1835710%2C1838587");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1832306%2C1834862%2C1835886%2C1836550%2C1837450");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1704420");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1813299");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1816287");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1821886");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1826002");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1832195");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1834711");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1837675");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1837993");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1839464");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=291640");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-3482: Block all cookies bypass for localstorage
When Firefox is configured to block storage of all cookies, it was still possible to store data in localstorage by using an iframe with a source of 'about:blank'. This could have led to malicious websites storing tracking data without permission.

CVE-2023-37201: Use-after-free in WebRTC certificate generation
An attacker could have triggered a use-after-free condition when creating a WebRTC connection over HTTPS.

CVE-2023-37202: Potential use-after-free from compartment mismatch in SpiderMonkey
Cross-compartment wrappers wrapping a scripted proxy could have caused objects from other compartments to be stored in the main compartment resulting in a use-after-free.

CVE-2023-37203: Drag and Drop API may provide access to local system files
Insufficient validation in the Drag and Drop API in conjunction with social engineering, may have allowed an attacker to trick end-users into creating a shortcut to local system files. This could have been leveraged to execute arbitrary code.

CVE-2023-37204: Fullscreen notification obscured via option element
A website could have obscured the fullscreen notification by using an option element by introducing lag via an expensive computational function. This could have led to user confusion and possible spoofing attacks.

CVE-2023-37205: URL spoofing in address bar using RTL characters
The use of RTL Arabic characters in the address bar may have allowed for URL spoofing.

CVE-2023-37206: Insufficient validation of symlinks in the FileSystem API
Uploading files which contain symlinks may have allowed an attacker to trick a user into submitting sensitive data to a malicious website.

CVE-2023-37207: Fullscreen notification obscured
A website could have obscured the fullscreen notification by using a URL with a scheme handled by an external program, such as a mailto URL. This could have led to user confusion and possible spoofing attacks.

CVE-2023-37208: Lack of warning when opening Diagcab files
When opening Diagcab files, Firefox did not warn the user that these files may contain malicious code.

CVE-2023-37209: Use-after-free in `NotifyOnHistoryReload`
A use-after-free condition existed in NotifyOnHistoryReload where a LoadingSessionHistoryEntry object was freed and a reference to that object remained. This resulted in a potentially exploitable condition when the reference to that object was later reused.

CVE-2023-37210: Full-screen mode exit prevention
A website could prevent a user from exiting full-screen mode via alert and prompt calls. This could lead to user confusion and possible spoofing attacks.

CVE-2023-37211: Memory safety bugs fixed in Firefox 115, Firefox ESR 102.13, and Thunderbird 102.13
Memory safety bugs present in Firefox 114, Firefox ESR 102.12, and Thunderbird 102.12. Some of these bugs showed evidence of memory corruption and we presume that with enough ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 115.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the reference(s) for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "115")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "115", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
