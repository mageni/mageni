# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2023.56");
  script_cve_id("CVE-2023-6135", "CVE-2023-6856", "CVE-2023-6857", "CVE-2023-6858", "CVE-2023-6859", "CVE-2023-6860", "CVE-2023-6861", "CVE-2023-6863", "CVE-2023-6864", "CVE-2023-6865", "CVE-2023-6866", "CVE-2023-6867", "CVE-2023-6869", "CVE-2023-6871", "CVE-2023-6872", "CVE-2023-6873");
  script_tag(name:"creation_date", value:"2023-12-20 09:22:47 +0000 (Wed, 20 Dec 2023)");
  script_version("2023-12-26T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-26 05:05:23 +0000 (Tue, 26 Dec 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-22 10:28:00 +0000 (Fri, 22 Dec 2023)");

  script_name("Mozilla Firefox Security Advisory (MFSA2023-56) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2023-56");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-56/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1736385%2C1810805%2C1846328%2C1856090%2C1858033%2C1858509%2C1862777%2C1864015");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1855327%2C1862089%2C1862723");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1796023");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1799036");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1826791");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1828334");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1840144");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1843782");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1849037");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1849186");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1853908");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1854669");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1863863");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1864118");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1864123");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1868901");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-6856: Heap-buffer-overflow affecting WebGL DrawElementsInstanced method with Mesa VM driver
The WebGL DrawElementsInstanced method was susceptible to a heap buffer overflow when used on systems with the Mesa VM driver. This issue could allow an attacker to perform remote code execution and sandbox escape.

CVE-2023-6135: NSS susceptible to 'Minerva' attack
Multiple NSS NIST curves were susceptible to a side-channel attack known as 'Minerva'. This attack could potentially allow an attacker to recover the private key.

CVE-2023-6865: Potential exposure of uninitialized data in EncryptingOutputStream
EncryptingOutputStream was susceptible to exposing uninitialized data. This issue could only be abused in order to write data to a local disk which may have implications for private browsing mode.

CVE-2023-6857: Symlinks may resolve to smaller than expected buffers
When resolving a symlink, a race may occur where the buffer passed to readlink may actually be smaller than necessary. This bug only affects Firefox on Unix-based operating systems (Android, Linux, MacOS). Windows is unaffected.

CVE-2023-6858: Heap buffer overflow in nsTextFragment
Firefox was susceptible to a heap buffer overflow in nsTextFragment due to insufficient OOM handling.

CVE-2023-6859: Use-after-free in PR_GetIdentitiesLayer
A use-after-free condition affected TLS socket creation when under memory pressure.

CVE-2023-6866: TypedArrays lack sufficient exception handling
TypedArrays can be fallible and lacked proper exception handling. This could lead to abuse in other APIs which expect TypedArrays to always succeed.

CVE-2023-6860: Potential sandbox escape due to VideoBridge lack of texture validation
The VideoBridge allowed any content process to use textures produced by remote decoders. This could be abused to escape the sandbox.

CVE-2023-6867: Clickjacking permission prompts using the popup transition
The timing of a button click causing a popup to disappear was approximately the same length as the anti-clickjacking delay on permission prompts. It was possible to use this fact to surprise users by luring them to click where the permission grant button would be about to appear.

CVE-2023-6861: Heap buffer overflow affected nsWindow::PickerOpen(void) in headless mode
The nsWindow::PickerOpen(void) method was susceptible to a heap buffer overflow when running in headless mode.

CVE-2023-6869: Content can paint outside of sandboxed iframe
A <dialog> element could have been manipulated to paint content outside of a sandboxed iframe. This could allow untrusted content ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 121.");

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

if (version_is_less(version: version, test_version: "121")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "121", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
