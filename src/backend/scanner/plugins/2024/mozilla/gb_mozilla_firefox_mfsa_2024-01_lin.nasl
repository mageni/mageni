# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2024.01");
  script_cve_id("CVE-2024-0741", "CVE-2024-0742", "CVE-2024-0743", "CVE-2024-0744", "CVE-2024-0745", "CVE-2024-0746", "CVE-2024-0747", "CVE-2024-0748", "CVE-2024-0749", "CVE-2024-0750", "CVE-2024-0751", "CVE-2024-0752", "CVE-2024-0753", "CVE-2024-0754", "CVE-2024-0755");
  script_tag(name:"creation_date", value:"2024-01-24 07:02:00 +0000 (Wed, 24 Jan 2024)");
  script_version("2024-01-30T14:37:03+0000");
  script_tag(name:"last_modification", value:"2024-01-30 14:37:03 +0000 (Tue, 30 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-29 22:47:00 +0000 (Mon, 29 Jan 2024)");

  script_name("Mozilla Firefox Security Advisory (MFSA2024-01) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2024-01");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-01/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1868456%2C1871445%2C1873701");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1660223");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1764343");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1783504");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1813463");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1863083");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1864587");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1865689");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1866840");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1867152");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1867408");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1870262");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1871089");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1871605");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1871838");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-0741: Out of bounds write in ANGLE
An out of bounds write in ANGLE could have allowed an attacker to corrupt memory leading to a potentially exploitable crash.

CVE-2024-0742: Failure to update user input timestamp
It was possible for certain browser prompts and dialogs to be activated or dismissed unintentionally by the user due to an incorrect timestamp used to prevent input after page load.

CVE-2024-0743: Crash in NSS TLS method
An unchecked return value in TLS handshake code could have caused a potentially exploitable crash.

CVE-2024-0744: Wild pointer dereference in JavaScript
In some circumstances, JIT compiled code could have dereferenced a wild pointer value. This could have led to an exploitable crash.

CVE-2024-0745: Stack buffer overflow in WebAudio
The WebAudio OscillatorNode object was susceptible to a stack buffer overflow. This could have led to a potentially exploitable crash.

CVE-2024-0746: Crash when listing printers on Linux
A Linux user opening the print preview dialog could have caused the browser to crash.

CVE-2024-0747: Bypass of Content Security Policy when directive unsafe-inline was set
When a parent page loaded a child in an iframe with unsafe-inline, the parent Content Security Policy could have overridden the child Content Security Policy.

CVE-2024-0748: Compromised content process could modify document URI
A compromised content process could have updated the document URI. This could have allowed an attacker to set an arbitrary URI in the address bar or history.

CVE-2024-0749: Phishing site popup could show local origin in address bar
A phishing site could have repurposed an about: dialog to show phishing content with an incorrect origin in the address bar.

CVE-2024-0750: Potential permissions request bypass via clickjacking
A bug in popup notifications delay calculation could have made it possible for an attacker to trick a user into granting permissions.

CVE-2024-0751: Privilege escalation through devtools
A malicious devtools extension could have been used to escalate privileges.

CVE-2024-0752: Use-after-free could occur when applying update on macOS
A use-after-free crash could have occurred on macOS if a Firefox update were being applied on a very busy system. This could have resulted in an exploitable crash.

CVE-2024-0753: HSTS policy on subdomain could bypass policy of upper domain
In specific HSTS configurations an attacker could have bypassed HSTS on a subdomain.

CVE-2024-0754: Crash when using some WASM files in devtools
Some WASM source files could have caused a crash when loaded in devtools.

CVE-2024-0755: Memory safety bugs fixed in Firefox 122, Firefox ESR 115.7, and Thunderbird 115.7
Memory safety bugs present in Firefox 121, Firefox ESR 115.6, and Thunderbird 115.6. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 122.");

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

if (version_is_less(version: version, test_version: "122")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "122", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
