# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2023.34");
  script_cve_id("CVE-2023-4573", "CVE-2023-4574", "CVE-2023-4575", "CVE-2023-4577", "CVE-2023-4578", "CVE-2023-4579", "CVE-2023-4580", "CVE-2023-4581", "CVE-2023-4583", "CVE-2023-4584", "CVE-2023-4585");
  script_tag(name:"creation_date", value:"2023-09-04 10:11:56 +0000 (Mon, 04 Sep 2023)");
  script_version("2023-09-08T16:09:14+0000");
  script_tag(name:"last_modification", value:"2023-09-08 16:09:14 +0000 (Fri, 08 Sep 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mozilla Firefox Security Advisory (MFSA2023-34) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2023-34");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-34/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1839007");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1842030");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1842766");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1843046");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1843758");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1846687");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1846688");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1846689");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1847397");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-4573: Memory corruption in IPC CanvasTranslator
When receiving rendering data over IPC mStream could have been destroyed when initialized, which could have led to a use-after-free causing a potentially exploitable crash.

CVE-2023-4574: Memory corruption in IPC ColorPickerShownCallback
When creating a callback over IPC for showing the Color Picker window, multiple of the same callbacks could have been created at a time and eventually all simultaneously destroyed as soon as one of the callbacks finished. This could have led to a use-after-free causing a potentially exploitable crash.

CVE-2023-4575: Memory corruption in IPC FilePickerShownCallback
When creating a callback over IPC for showing the File Picker window, multiple of the same callbacks could have been created at a time and eventually all simultaneously destroyed as soon as one of the callbacks finished. This could have led to a use-after-free causing a potentially exploitable crash.

CVE-2023-4577: Memory corruption in JIT UpdateRegExpStatics
When UpdateRegExpStatics attempted to access initialStringHeap it could already have been garbage collected prior to entering the function, which could potentially have led to an exploitable crash.

CVE-2023-4578: Error reporting methods in SpiderMonkey could have triggered an Out of Memory Exception
When calling JS::CheckRegExpSyntax a Syntax Error could have been set which would end in calling convertToRuntimeErrorAndClear. A path in the function could attempt to allocate memory when none is available which would have caused a newly created Out of Memory exception to be mishandled as a Syntax Error.

CVE-2023-4579: Persisted search terms were formatted as URLs
Search queries in the default search engine could appear to have been the currently navigated URL if the search query itself was a well formed URL. This could have led to a site spoofing another if it had been maliciously set as the default search engine.

CVE-2023-4580: Push notifications saved to disk unencrypted
Push notifications stored on disk in private browsing mode were not being encrypted potentially allowing the leak of sensitive information.

CVE-2023-4581: XLL file extensions were downloadable without warnings
Excel .xll add-in files did not have a blocklist entry in Firefox's executable blocklist which allowed them to be downloaded without any warning of their potential harm.

... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 117.");

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

if (version_is_less(version: version, test_version: "117")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "117", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
