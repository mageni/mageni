# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2023.16");
  script_cve_id("CVE-2023-32205", "CVE-2023-32206", "CVE-2023-32207", "CVE-2023-32208", "CVE-2023-32209", "CVE-2023-32210", "CVE-2023-32211", "CVE-2023-32212", "CVE-2023-32213", "CVE-2023-32215", "CVE-2023-32216");
  script_tag(name:"creation_date", value:"2023-05-10 05:57:51 +0000 (Wed, 10 May 2023)");
  script_version("2023-05-10T09:37:12+0000");
  script_tag(name:"last_modification", value:"2023-05-10 09:37:12 +0000 (Wed, 10 May 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mozilla Firefox Security Advisory (MFSA2023-16) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2023-16");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-16/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1540883%2C1751943%2C1814856%2C1820210%2C1821480%2C1827019%2C1827024%2C1827144%2C1827359%2C1830186");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1746479%2C1806852%2C1815987%2C1820359%2C1823568%2C1824803%2C1824834%2C1825170%2C1827020%2C1828130");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1646034");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1753339");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1753341");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1767194");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1776755");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1814560");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1814790");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1819796");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1823379");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1824892");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1826116");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1826622");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1826666");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-32205: Browser prompts could have been obscured by popups
In multiple cases browser prompts could have been obscured by popups controlled by content. These could have led to potential user confusion and spoofing attacks.

CVE-2023-32206: Crash in RLBox Expat driver
An out-of-bound read could have led to a crash in the RLBox Expat driver.

CVE-2023-32207: Potential permissions request bypass via clickjacking
A missing delay in popup notifications could have made it possible for an attacker to trick a user into granting permissions.

CVE-2023-32208: Leak of script base URL in service workers via import()
Service workers could reveal script base URL due to dynamic import().

CVE-2023-32209: Persistent DoS via favicon image
A maliciously crafted favicon could have led to an out of memory crash.

CVE-2023-32210: Incorrect principal object ordering
Documents were incorrectly assuming an ordering of principal objects when ensuring we were loading an appropriately privileged principal. In certain circumstances it might have been possible to cause a document to be loaded with a higher privileged principal than intended.

CVE-2023-32211: Content process crash due to invalid wasm code
A type checking bug would have led to invalid code being compiled.

CVE-2023-32212: Potential spoof due to obscured address bar
An attacker could have positioned a datalist element to obscure the address bar.

CVE-2023-32213: Potential memory corruption in FileReader::DoReadData()
When reading a file, an uninitialized value could have been used as read limit.

MFSA-TMP-2023-0002: Race condition in dav1d decoding
A race condition during dav1d decoding could have led to an out-of-bounds memory access, potentially leading to memory corruption and execution of malicious code.

CVE-2023-32215: Memory safety bugs fixed in Firefox 113 and Firefox ESR 102.11
Mozilla developers and community members Gabriele Svelto, Andrew Osmond, Emily McDonough, Sebastian Hengst, Andrew McCreight and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 112 and Firefox ESR 102.10. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2023-32216: Memory safety bugs fixed in Firefox 113
Mozilla developers and community members Ronald Crane, Andrew McCreight, Randell Jesup and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 112. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 113.");

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

if (version_is_less(version: version, test_version: "113")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "113", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
