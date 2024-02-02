# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2023.45");
  script_cve_id("CVE-2023-5721", "CVE-2023-5722", "CVE-2023-5723", "CVE-2023-5724", "CVE-2023-5725", "CVE-2023-5728", "CVE-2023-5729", "CVE-2023-5730", "CVE-2023-5731");
  script_tag(name:"creation_date", value:"2023-10-24 14:39:01 +0000 (Tue, 24 Oct 2023)");
  script_version("2023-11-03T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-01 19:27:00 +0000 (Wed, 01 Nov 2023)");

  script_name("Mozilla Firefox Security Advisory (MFSA2023-45) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2023-45");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-45/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1690111%2C1721904%2C1851803%2C1854068");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1836607%2C1840918%2C1848694%2C1848833%2C1850191%2C1850259%2C1852596%2C1853201%2C1854002%2C1855306%2C1855640%2C1856695");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1738426");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1802057");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1823720");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1830820");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1836705");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1845739");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1852729");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-5721: Queued up rendering could have allowed websites to clickjack
It was possible for certain browser prompts and dialogs to be activated or dismissed unintentionally by the user due to an insufficient activation-delay.

CVE-2023-5722: Cross-Origin size and header leakage
Using iterative requests an attacker was able to learn the size of an opaque response, as well as the contents of a server-supplied Vary header.

CVE-2023-5723: Invalid cookie characters could have led to unexpected errors
An attacker with temporary script access to a site could have set a cookie containing invalid characters using document.cookie that could have led to unknown errors.

CVE-2023-5724: Large WebGL draw could have led to a crash
Drivers are not always robust to extremely large draw calls and in some cases this scenario could have led to a crash.

CVE-2023-5725: WebExtensions could open arbitrary URLs
A malicious installed WebExtension could open arbitrary URLs, which under the right circumstance could be leveraged to collect sensitive user data.

CVE-2023-5728: Improper object tracking during GC in the JavaScript engine could have led to a crash.
During garbage collection extra operations were performed on a object that should not be. This could have led to a potentially exploitable crash.

CVE-2023-5729: Fullscreen notification dialog could have been obscured by WebAuthn prompts
A malicious web site can enter fullscreen mode while simultaneously triggering a WebAuthn prompt. This could have obscured the fullscreen notification and could have been leveraged in a spoofing attack.

CVE-2023-5730: Memory safety bugs fixed in Firefox 119, Firefox ESR 115.4, and Thunderbird 115.4
Memory safety bugs present in Firefox 118, Firefox ESR 115.3, and Thunderbird 115.3. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2023-5731: Memory safety bugs fixed in Firefox 119
Memory safety bugs present in Firefox 118. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 119.");

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

if (version_is_less(version: version, test_version: "119")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "119", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
