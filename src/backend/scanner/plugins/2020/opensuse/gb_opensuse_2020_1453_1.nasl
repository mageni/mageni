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
  script_oid("1.3.6.1.4.1.25623.1.0.853433");
  script_version("2020-09-28T10:54:24+0000");
  script_cve_id("CVE-2020-17353");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-09-29 10:01:49 +0000 (Tue, 29 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-20 03:00:48 +0000 (Sun, 20 Sep 2020)");
  script_name("openSUSE: Security Advisory for lilypond (openSUSE-SU-2020:1453-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:1453-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00064.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lilypond'
  package(s) announced via the openSUSE-SU-2020:1453-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for lilypond fixes the following issues:

  - CVE-2020-17353: When -dsafe is used, LilyPond lacks restrictions on
  embedded-ps and embedded-svg (boo#1174949).


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1453=1

  - openSUSE Backports SLE-15-SP2:

  zypper in -t patch openSUSE-2020-1453=1");

  script_tag(name:"affected", value:"'lilypond' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc", rpm:"lilypond-doc~2.20.0~lp152.2.5.10", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-cs", rpm:"lilypond-doc-cs~2.20.0~lp152.2.5.10", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-de", rpm:"lilypond-doc-de~2.20.0~lp152.2.5.10", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-es", rpm:"lilypond-doc-es~2.20.0~lp152.2.5.10", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-fr", rpm:"lilypond-doc-fr~2.20.0~lp152.2.5.10", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-hu", rpm:"lilypond-doc-hu~2.20.0~lp152.2.5.10", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-it", rpm:"lilypond-doc-it~2.20.0~lp152.2.5.10", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-ja", rpm:"lilypond-doc-ja~2.20.0~lp152.2.5.10", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-nl", rpm:"lilypond-doc-nl~2.20.0~lp152.2.5.10", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-doc-zh", rpm:"lilypond-doc-zh~2.20.0~lp152.2.5.10", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-emmentaler-fonts", rpm:"lilypond-emmentaler-fonts~2.20.0~lp152.2.5.10", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-fonts-common", rpm:"lilypond-fonts-common~2.20.0~lp152.2.5.10", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-texgy-fonts", rpm:"lilypond-texgy-fonts~2.20.0~lp152.2.5.10", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond", rpm:"lilypond~2.20.0~lp152.2.5.10", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-debuginfo", rpm:"lilypond-debuginfo~2.20.0~lp152.2.5.10", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lilypond-debugsource", rpm:"lilypond-debugsource~2.20.0~lp152.2.5.10", rls:"openSUSELeap15.2"))) {
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