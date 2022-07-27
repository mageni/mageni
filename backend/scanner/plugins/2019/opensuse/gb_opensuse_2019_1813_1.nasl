# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852643");
  script_version("2019-08-08T09:10:13+0000");
  script_cve_id("CVE-2019-11709", "CVE-2019-11711", "CVE-2019-11712", "CVE-2019-11713",
                "CVE-2019-11715", "CVE-2019-11717", "CVE-2019-11719", "CVE-2019-11729",
                "CVE-2019-11730", "CVE-2019-9811");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-08-08 09:10:13 +0000 (Thu, 08 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-07-31 02:01:36 +0000 (Wed, 31 Jul 2019)");
  script_name("openSUSE Update for MozillaThunderbird openSUSE-SU-2019:1813-1 (MozillaThunderbird)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-07/msg00058.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the openSUSE-SU-2019:1813_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird version 60.8 fixes the following issues:

  Security issues fixed:

  - CVE-2019-9811: Sandbox escape via installation of malicious language
  pack (bsc#1140868).

  - CVE-2019-11711: Script injection within domain through inner window
  reuse (bsc#1140868).

  - CVE-2019-11712: Cross-origin POST requests can be made with NPAPI
  plugins by following 308 redirects (bsc#1140868).

  - CVE-2019-11713: Use-after-free with HTTP/2 cached stream (bsc#1140868).

  - CVE-2019-11729: Empty or malformed p256-ECDH public keys may trigger a
  segmentation fault (bsc#1140868).

  - CVE-2019-11715: HTML parsing error can contribute to content XSS
  (bsc#1140868).

  - CVE-2019-11717: Caret character improperly escaped in origins
  (bsc#1140868).

  - CVE-2019-11719: Out-of-bounds read when importing curve25519 private key
  (bsc#1140868).

  - CVE-2019-11730: Same-origin policy treats all files in a directory as
  having the same-origin (bsc#1140868).

  - CVE-2019-11709: Multiple Memory safety bugs fixed (bsc#1140868).

  Non-security issued fixed:

  - Calendar: Problems when editing event times, some related to AM/PM
  setting in non-English locales

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1813=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1813=1");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~60.8.0~lp150.3.48.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~60.8.0~lp150.3.48.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~60.8.0~lp150.3.48.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~60.8.0~lp150.3.48.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~60.8.0~lp150.3.48.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~60.8.0~lp150.3.48.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
