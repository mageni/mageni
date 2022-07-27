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
  script_oid("1.3.6.1.4.1.25623.1.0.852726");
  script_version("2019-10-11T07:39:42+0000");
  script_cve_id("CVE-2019-11709", "CVE-2019-11710", "CVE-2019-11711", "CVE-2019-11712", "CVE-2019-11713", "CVE-2019-11714", "CVE-2019-11715", "CVE-2019-11716", "CVE-2019-11717", "CVE-2019-11719", "CVE-2019-11720", "CVE-2019-11721", "CVE-2019-11723", "CVE-2019-11724", "CVE-2019-11725", "CVE-2019-11727", "CVE-2019-11728", "CVE-2019-11729", "CVE-2019-11730", "CVE-2019-11739", "CVE-2019-11740", "CVE-2019-11742", "CVE-2019-11743", "CVE-2019-11744", "CVE-2019-11746", "CVE-2019-11752", "CVE-2019-11755");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-10-11 07:39:42 +0000 (Fri, 11 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-05 02:00:58 +0000 (Sat, 05 Oct 2019)");
  script_name("openSUSE Update for MozillaThunderbird openSUSE-SU-2019:2248-1 (MozillaThunderbird)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-10/msg00010.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the openSUSE-SU-2019:2248_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird to version 68.1.1 fixes the following
  issues:

  - CVE-2019-11709: Fixed several memory safety bugs. (bsc#1140868)

  - CVE-2019-11710: Fixed several memory safety bugs. (bsc#1140868)

  - CVE-2019-11711: Fixed a script injection within domain through inner
  window reuse. (bsc#1140868)

  - CVE-2019-11712: Fixed an insufficient validation of cross-origin POST
  requests within NPAPI plugins. (bsc#1140868)

  - CVE-2019-11713: Fixed a use-after-free with HTTP/2 cached stream.
  (bsc#1140868)

  - CVE-2019-11714: Fixed a crash in NeckoChild. (bsc#1140868)

  - CVE-2019-11715: Fixed an HTML parsing error that can contribute to
  content XSS. (bsc#1140868)

  - CVE-2019-11716: Fixed an enumeration issue in globalThis. (bsc#1140868)

  - CVE-2019-11717: Fixed an improper escaping of the caret character in
  origins. (bsc#1140868)

  - CVE-2019-11719: Fixed an out-of-bounds read when importing curve25519
  private key. (bsc#1140868)

  - CVE-2019-11720: Fixed a character encoding XSS vulnerability.
  (bsc#1140868)

  - CVE-2019-11721: Fixed domain spoofing through unicode latin 'kra'
  character. (bsc#1140868)

  - CVE-2019-11723: Fixed a cookie leakage during add-on fetching across
  private browsing boundaries. (bsc#1140868)

  - CVE-2019-11724: Fixed a permissions issue with the retired site
  input.mozilla.org. (bsc#1140868)

  - CVE-2019-11725: Fixed a SafeBrowsing bypass through WebSockets.
  (bsc#1140868)

  - CVE-2019-11727: Fixed an insufficient validation for PKCS#1 v1.5
  signatures being used with TLS 1.3. (bsc#1140868)

  - CVE-2019-11728: Fixed port scanning through Alt-Svc header. (bsc#1140868)

  - CVE-2019-11729: Fixed a segmentation fault due to empty or malformed
  p256-ECDH public keys. (bsc#1140868)

  - CVE-2019-11730: Fixed an insufficient enforcement of the same-origin
  policy that treats all files in a directory as having the same-origin.
  (bsc#1140868)

  - CVE-2019-11739: Fixed a Covert Content Attack on S/MIME encryption using
  a crafted multipart/alternative message. (bsc#1150939)

  - CVE-2019-11740: Fixed several memory safety bugs. (bsc#1149299)

  - CVE-2019-11742: Fixed a same-origin policy violation with SVG filters
  and canvas that enabled theft of cross-origin images. (bsc#1149303)

  - CVE-2019-11743: Fixed a cross-origin access issue. (bsc#1149298)

  - CVE-2019-11744: Fixed a XSS involving breaking out of title and textarea
  elements using innerHTML. (bsc#1149304)

  - CVE-2019-11746: Fixed a use-after-free while manipulating video.
  (bsc#1149297)

  - CVE-2019-11752: Fixed a use-after-free while extracting a key value in
  ...

  Description truncated. Please see the references for more information.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~68.1.1~lp150.3.51.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~68.1.1~lp150.3.51.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~68.1.1~lp150.3.51.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~68.1.1~lp150.3.51.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~68.1.1~lp150.3.51.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~68.1.1~lp150.3.51.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"enigmail", rpm:"enigmail~2.1.2~lp150.34.1", rls:"openSUSELeap15.0"))) {
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