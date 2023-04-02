# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2023.09");
  script_cve_id("CVE-2023-25750", "CVE-2023-25751", "CVE-2023-25752", "CVE-2023-28160", "CVE-2023-28161", "CVE-2023-28162", "CVE-2023-28164", "CVE-2023-28176", "CVE-2023-28177");
  script_tag(name:"creation_date", value:"2023-03-14 14:52:07 +0000 (Tue, 14 Mar 2023)");
  script_version("2023-03-24T10:09:03+0000");
  script_tag(name:"last_modification", value:"2023-03-24 10:09:03 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mozilla Firefox Security Advisory (MFSA2023-09) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2023-09");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-09/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1803109%2C1808832%2C1809542%2C1817336");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1808352%2C1811637%2C1815904%2C1817442%2C1818674");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1802385");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1809122");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1811181");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1811327");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1811627");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1814733");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1814899");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-25750: Potential ServiceWorker cache leak during private browsing mode
Under certain circumstances, a ServiceWorker's offline cache may have leaked to the file system when using private browsing mode.

CVE-2023-25751: Incorrect code generation during JIT compilation
Sometimes, when invalidating JIT code while following an iterator, the newly generated code could be overwritten incorrectly. This could lead to a potentially exploitable crash.

CVE-2023-28160: Redirect to Web Extension files may have leaked local path
When following a redirect to a publicly accessible web extension file, the URL may have been translated to the actual local path, leaking potentially sensitive information.

CVE-2023-28164: URL being dragged from a removed cross-origin iframe into the same tab triggered navigation
Dragging a URL from a cross-origin iframe that was removed during the drag could have lead to user confusion and website spoofing attacks.

CVE-2023-28161: One-time permissions granted to a local file were extended to other local files loaded in the same tab
If temporary 'one-time' permissions, such as the ability to use the Camera, were granted to a document loaded using a file: URL, that permission persisted in that tab for all other documents loaded from a file: URL. This is potentially dangerous if the local files came from different sources, such as in a download directory.

CVE-2023-28162: Invalid downcast in Worklets
While implementing on AudioWorklets, some code may have casted one type to another, invalid, dynamic type. This could have lead to a potentially exploitable crash.

CVE-2023-25752: Potential out-of-bounds when accessing throttled streams
When accessing throttled streams, the count of available bytes needed to be checked in the calling function to be within bounds. This may have lead future code to be incorrect and vulnerable.

CVE-2023-28176: Memory safety bugs fixed in Firefox 111 and Firefox ESR 102.9
Mozilla developers Timothy Nikkel, Andrew McCreight, and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 110 and Firefox ESR 102.8. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2023-28177: Memory safety bugs fixed in Firefox 111
Mozilla developers and community members Calixte Denizet, Gabriele Svelto, Andrew McCreight, and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 110. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 111.");

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

if (version_is_less(version: version, test_version: "111")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "111", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
