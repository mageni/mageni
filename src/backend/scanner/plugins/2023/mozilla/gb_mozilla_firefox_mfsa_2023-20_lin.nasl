# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2023.20");
  script_cve_id("CVE-2023-34414", "CVE-2023-34415", "CVE-2023-34416", "CVE-2023-34417");
  script_tag(name:"creation_date", value:"2023-06-07 06:46:32 +0000 (Wed, 07 Jun 2023)");
  script_version("2023-06-08T05:05:11+0000");
  script_tag(name:"last_modification", value:"2023-06-08 05:05:11 +0000 (Thu, 08 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mozilla Firefox Security Advisory (MFSA2023-20) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2023-20");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-20/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1746447%2C1820903%2C1832832");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1752703%2C1818394%2C1826875%2C1827340%2C1827655%2C1828065%2C1830190%2C1830206%2C1830795%2C1833339");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1695986");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1811999");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-34414: Click-jacking certificate exceptions through rendering lag
The error page for sites with invalid TLS certificates was missing the
activation-delay Firefox uses to protect prompts and permission dialogs
from attacks that exploit human response time delays. If a malicious
page elicited user clicks in precise locations immediately before
navigating to a site with a certificate error and made the renderer
extremely busy at the same time, it could create a gap between when
the error page was loaded and when the display actually refreshed.
With the right timing the elicited clicks could land in that gap and
activate the button that overrides the certificate error for that site.

CVE-2023-34415: Site-isolation bypass on sites that allow open redirects to data: urls
When choosing a site-isolated process for a document loaded from a
data: URL that was the result of a redirect, Firefox would load that
document in the same process as the site that issued the redirect. This
bypassed the site-isolation protections against Spectre-like attacks
on sites that host an 'open redirect'. Firefox no longer follows HTTP
redirects to data: URLs.

CVE-2023-34416: Memory safety bugs fixed in Firefox 114 and Firefox ESR 102.12
Mozilla developers and community members Gabriele Svelto, Andrew McCreight,
the Mozilla Fuzzing Team, Sean Feng, and Sebastian Hengst reported memory
safety bugs present in Firefox 113 and Firefox ESR 102.11. Some of these
bugs showed evidence of memory corruption and we presume that with enough
effort some of these could have been exploited to run arbitrary code.

CVE-2023-34417: Memory safety bugs fixed in Firefox 114
Mozilla developers and community members Andrew McCreight, Randell Jesup,
and the Mozilla Fuzzing Team reported memory safety bugs present in
Firefox 113. Some of these bugs showed evidence of memory corruption
and we presume that with enough effort some of these could have been
exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 114.");

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

if (version_is_less(version: version, test_version: "114")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "114", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
