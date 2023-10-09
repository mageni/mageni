# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2023.41");
  script_cve_id("CVE-2023-5169", "CVE-2023-5170", "CVE-2023-5171", "CVE-2023-5172", "CVE-2023-5173", "CVE-2023-5175", "CVE-2023-5176");
  script_tag(name:"creation_date", value:"2023-09-26 13:51:59 +0000 (Tue, 26 Sep 2023)");
  script_version("2023-09-29T05:05:51+0000");
  script_tag(name:"last_modification", value:"2023-09-29 05:05:51 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mozilla Firefox Security Advisory (MFSA2023-41) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2023-41");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-41/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1836353%2C1842674%2C1843824%2C1843962%2C1848890%2C1850180%2C1850983%2C1851195");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1823172");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1846685");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1846686");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1849704");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1851599");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1852218");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-5169: Out-of-bounds write in PathOps
A compromised content process could have provided malicious data in a PathRecording resulting in an out-of-bounds write, leading to a potentially exploitable crash in a privileged process.

CVE-2023-5170: Memory leak from a privileged process
In canvas rendering, a compromised content process could have caused a surface to change unexpectedly, leading to a memory leak of a privileged process. This memory leak could be used to effect a sandbox escape if the correct data was leaked.

CVE-2023-5171: Use-after-free in Ion Compiler
During Ion compilation, a Garbage Collection could have resulted in a use-after-free condition, allowing an attacker to write two NUL bytes, and cause a potentially exploitable crash.

CVE-2023-5172: Memory Corruption in Ion Hints
A hashtable in the Ion Engine could have been mutated while there was a live interior reference, leading to a potential use-after-free and exploitable crash.

CVE-2023-5173: Out-of-bounds write in HTTP Alternate Services
In a non-standard configuration of Firefox, an integer overflow could have occurred based on network traffic (possibly under influence of a local unprivileged webpage), leading to an out-of-bounds write to privileged process memory. This bug only affects Firefox if a non-standard preference allowing non-HTTPS Alternate Services (network.http.altsvc.oe) is enabled.

CVE-2023-5175: Use-after-free of ImageBitmap during process shutdown
During process shutdown, it was possible that an ImageBitmap was created that would later be used after being freed from a different codepath, leading to a potentially exploitable crash.

CVE-2023-5176: Memory safety bugs fixed in Firefox 118, Firefox ESR 115.3, and Thunderbird 115.3
Memory safety bugs present in Firefox 117, Firefox ESR 115.2, and Thunderbird 115.2. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 118.");

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

if (version_is_less(version: version, test_version: "118")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "118", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
