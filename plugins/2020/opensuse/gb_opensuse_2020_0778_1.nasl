# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.853198");
  script_version("2020-06-09T07:30:09+0000");
  script_cve_id("CVE-2020-13614");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-06-09 11:12:11 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-09 03:00:57 +0000 (Tue, 09 Jun 2020)");
  script_name("openSUSE: Security Advisory for axel (openSUSE-SU-2020:0778-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00006.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'axel'
  package(s) announced via the openSUSE-SU-2020:0778-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for axel fixes the following issues:

  axel was updated to 2.17.8:

  * CVE-2020-13614: SSL Certificate Hostnames were not verified (boo#1172159)

  * Replaced progressbar line clearing with terminal control sequence

  * Fixed parsing of Content-Disposition HTTP header

  * Fixed User-Agent HTTP header never being included

  Update to version 2.17.7:

  - Buildsystem fixes

  - Fixed release date for man-pages on BSD

  - Explicitly close TCP sockets on SSL connections too

  - Fixed HTTP basic auth header generation

  - Changed the default progress report to 'alternate output mode'

  - Improved English in README.md

  Update to version 2.17.6:

  - Fixed handling of non-recoverable HTTP errors

  - Cleanup of connection setup code

  - Fixed manpage reproducibility issue

  - Use tracker instead of PTS from Debian

  Update to version 2.17.5:

  - Fixed progress indicator misalignment

  - Cleaned up the wget-like progress output code

  - Improved progress output flushing

  Update to version 2.17.4:

  - Fixed build with bionic libc (Android)

  - TCP Fast Open support on Linux

  - TCP code cleanup

  - Removed dependency on libm

  - Data types and format strings cleanup

  - String handling cleanup

  - Format string checking GCC attributes added

  - Buildsystem fixes and improvements

  - Updates to the documentation

  - Updated all translations

  - Fixed Footnotes in documentation

  - Fixed a typo in README.md

  Update to version 2.17.3:

  - Builds now use canonical host triplet instead of `uname -s`

  - Fixed build on Darwin / Mac OS X

  - Fixed download loops caused by last byte pointer being off by one

  - Fixed linking issues (i18n and posix threads)

  - Updated build instructions

  - Code cleanup

  - Added autoconf-archive to building instructions

  Update to version 2.17.2:

  - Fixed HTTP request-ranges to be zero-based

  - Fixed typo 'too may' -> 'too many'

  - Replaced malloc + memset calls with calloc

  - Sanitize progress bar buffer len passed to memset

  Update to version 2.17.1:

  - Fixed comparison error in axel_divide

  - Make sure maxconns is at least 1

  Update to version 2.17:

  - Fixed composition of URLs in redirections

  - Fixed request range calculation

  - Updated all translations

  - Updated build documentation

  - Major code cleanup

  - Cleanup of alternate progress output

  - Removed global string buffers

  - Fixed min and max macros

  - Moved User-Agent header to conf->add_header

  - Use integers for speed ratio and delay calculation

  - Added support for parsing IPv6 literal hostname

  - Fixed filename extraction from URL

  - Fixed request-targ ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'axel' package(s) on openSUSE Leap 15.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"axel", rpm:"axel~2.17.8~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"axel-debuginfo", rpm:"axel-debuginfo~2.17.8~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"axel-debugsource", rpm:"axel-debugsource~2.17.8~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);