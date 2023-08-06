# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2023.29");
  script_cve_id("CVE-2023-4045", "CVE-2023-4046", "CVE-2023-4047", "CVE-2023-4048", "CVE-2023-4049", "CVE-2023-4050", "CVE-2023-4051", "CVE-2023-4053", "CVE-2023-4055", "CVE-2023-4056", "CVE-2023-4057", "CVE-2023-4058");
  script_tag(name:"creation_date", value:"2023-08-02 09:37:17 +0000 (Wed, 02 Aug 2023)");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mozilla Firefox Security Advisory (MFSA2023-29) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2023-29");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-29/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1819160%2C1828024");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1820587%2C1824634%2C1839235%2C1842325%2C1843847");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1782561");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1821884");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1833876");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1837686");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1839073");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1839079");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1841368");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1841682");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1842658");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1843038");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-4045: Offscreen Canvas could have bypassed cross-origin restrictions
Offscreen Canvas did not properly track cross-origin tainting, which could have been used to access image data from another site in violation of same-origin policy.

CVE-2023-4046: Incorrect value used during WASM compilation
In some circumstances, a stale value could have been used for a global variable in WASM JIT analysis. This resulted in incorrect compilation and a potentially exploitable crash in the content process.

CVE-2023-4047: Potential permissions request bypass via clickjacking
A bug in popup notifications delay calculation could have made it possible for an attacker to trick a user into granting permissions.

CVE-2023-4048: Crash in DOMParser due to out-of-memory conditions
An out-of-bounds read could have led to an exploitable crash when parsing HTML with DOMParser in low memory situations.

CVE-2023-4049: Fix potential race conditions when releasing platform objects
Race conditions in reference counting code were found through code inspection. These could have resulted in potentially exploitable use-after-free vulnerabilities.

CVE-2023-4050: Stack buffer overflow in StorageManager
In some cases, an untrusted input stream was copied to a stack buffer without checking its size. This resulted in a potentially exploitable crash which could have led to a sandbox escape.

CVE-2023-4051: Full screen notification obscured by file open dialog
A website could have obscured the full screen notification by using the file open dialog. This could have led to user confusion and possible spoofing attacks.

CVE-2023-4053: Full screen notification obscured by external program
A website could have obscured the full screen notification by using a URL with a scheme handled by an external program, such as a mailto URL. This could have led to user confusion and possible spoofing attacks.

CVE-2023-4055: Cookie jar overflow caused unexpected cookie jar state
When the number of cookies per domain was exceeded in document.cookie, the actual cookie jar sent to the host was no longer consistent with expected cookie jar state. This could have ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 116.");

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

if (version_is_less(version: version, test_version: "116")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "116", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
