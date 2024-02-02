# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2023.49");
  script_cve_id("CVE-2023-6204", "CVE-2023-6205", "CVE-2023-6206", "CVE-2023-6207", "CVE-2023-6208", "CVE-2023-6209", "CVE-2023-6210", "CVE-2023-6211", "CVE-2023-6212", "CVE-2023-6213");
  script_tag(name:"creation_date", value:"2023-11-22 08:17:35 +0000 (Wed, 22 Nov 2023)");
  script_version("2023-12-01T05:05:39+0000");
  script_tag(name:"last_modification", value:"2023-12-01 05:05:39 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-28 19:29:00 +0000 (Tue, 28 Nov 2023)");

  script_name("Mozilla Firefox Security Advisory (MFSA2023-49) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2023-49");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-49/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1658432%2C1820983%2C1829252%2C1856072%2C1856091%2C1859030%2C1860943%2C1862782");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1849265%2C1851118%2C1854911");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1801501");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1841050");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1850200");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1854076");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1855345");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1857430");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1858570");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1861344");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-6204: Out-of-bound memory access in WebGL2 blitFramebuffer
On some systems--depending on the graphics settings and drivers--it was possible to force an out-of-bounds read and leak memory data into the images created on the canvas element.

CVE-2023-6205: Use-after-free in MessagePort::Entangled
It was possible to cause the use of a MessagePort after it had already
been freed, which could potentially have led to an exploitable crash.

CVE-2023-6206: Clickjacking permission prompts using the fullscreen transition
The black fade animation when exiting fullscreen is roughly
the length of the anti-clickjacking delay on permission prompts.
It was possible to use this fact to surprise users by luring them
to click where the permission grant button would be about to appear.

CVE-2023-6207: Use-after-free in ReadableByteStreamQueueEntry::Buffer
Ownership mismanagement led to a use-after-free in ReadableByteStreams

CVE-2023-6208: Using Selection API would copy contents into X11 primary selection.
When using X11, text selected by the page using the Selection API was erroneously copied into the primary selection, a temporary storage not unlike the clipboard.This bug only affects Firefox on X11. Other systems are unaffected.

CVE-2023-6209: Incorrect parsing of relative URLs starting with '///'
Relative URLs starting with three slashes were incorrectly parsed, and a
path-traversal '/../' part in the path could be used to override the
specified host. This could contribute to security problems in web sites.

CVE-2023-6210: Mixed-content resources not blocked in a javascript: pop-up
When an https: web page created a pop-up from a 'javascript:' URL,
that pop-up was incorrectly allowed to load blockable content such
as iframes from insecure http: URLs

CVE-2023-6211: Clickjacking to load insecure pages in HTTPS-only mode
If an attacker needed a user to load an insecure http: page and knew
that user had enabled HTTPS-only mode, the attacker could have
tricked the user into clicking to grant an HTTPS-only exception
if they could get the user to participate in a clicking game.

CVE-2023-6212: Memory safety bugs fixed in Firefox 120, Firefox ESR 115.5, and Thunderbird 115.5
Memory safety bugs present in Firefox 119, Firefox ESR 115.4, and Thunderbird 115.4. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2023-6213: Memory safety bugs fixed in Firefox 120
Memory safety bugs present in Firefox 119. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 120.");

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

if (version_is_less(version: version, test_version: "120")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "120", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
