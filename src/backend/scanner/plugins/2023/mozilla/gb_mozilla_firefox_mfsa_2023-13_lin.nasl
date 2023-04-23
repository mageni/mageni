# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2023.13");
  script_cve_id("CVE-2023-1999", "CVE-2023-28163", "CVE-2023-29532", "CVE-2023-29533", "CVE-2023-29535", "CVE-2023-29536", "CVE-2023-29537", "CVE-2023-29538", "CVE-2023-29539", "CVE-2023-29540", "CVE-2023-29541", "CVE-2023-29543", "CVE-2023-29544", "CVE-2023-29547", "CVE-2023-29548", "CVE-2023-29549", "CVE-2023-29550", "CVE-2023-29551");
  script_tag(name:"creation_date", value:"2023-04-12 07:19:25 +0000 (Wed, 12 Apr 2023)");
  script_version("2023-04-18T10:10:05+0000");
  script_tag(name:"last_modification", value:"2023-04-18 10:10:05 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mozilla Firefox Security Advisory (MFSA2023-13) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2023-13");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-13/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1720594%2C1812498%2C1814217%2C1818357%2C1751945%2C1818762%2C1819493%2C1820389%2C1820602%2C1821448%2C1822413%2C1824828");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1763625%2C1814314%2C1815798%2C1815890%2C1819239%2C1819465%2C1819486%2C1819492%2C1819957%2C1820514%2C1820776%2C1821838%2C1822175%2C1823547");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1685403");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1783536");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1784348");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1790542");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1798219");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1810191");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1814597");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1816158");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1818781");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1819244");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1820543");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1821959");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1822754");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1823042");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1823365");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1824200");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1825569");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-29533: Fullscreen notification obscured
A website could have obscured the fullscreen notification by using a combination of window.open, fullscreen requests, window.name assignments, and setInterval calls. This could have led to user confusion and possible spoofing attacks.

CVE-2023-1999: Double-free in libwebp
A double-free in libwebp could have led to memory corruption and a potentially exploitable crash.

CVE-2023-29535: Potential Memory Corruption following Garbage Collector compaction
Following a Garbage Collector compaction, weak maps may have been accessed before they were correctly traced. This resulted in memory corruption and a potentially exploitable crash.

CVE-2023-29536: Invalid free from JavaScript code
An attacker could cause the memory manager to incorrectly free a pointer that addresses attacker-controlled memory, resulting in an assertion, memory corruption, or a potentially exploitable crash.

CVE-2023-29537: Data Races in font initialization code
Multiple race conditions in the font initialization could have led to memory corruption and execution of attacker-controlled code.

CVE-2023-29538: Directory information could have been leaked to WebExtensions
Under specific circumstances a WebExtension may have received a jar:file:/// URI instead of a moz-extension:/// URI during a load request. This leaked directory paths on the user's machine.

CVE-2023-29539: Content-Disposition filename truncation leads to Reflected File Download
When handling the filename directive in the Content-Disposition header, the filename would be truncated if the filename contained a NULL character. This could have led to reflected file download attacks potentially tricking users to install malware.

CVE-2023-29540: Iframe sandbox bypass using ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 112.");

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

if (version_is_less(version: version, test_version: "112")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "112", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
