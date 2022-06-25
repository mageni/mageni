# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853078");
  script_version("2020-03-26T07:27:53+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-03-26 10:47:35 +0000 (Thu, 26 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-24 04:00:59 +0000 (Tue, 24 Mar 2020)");
  script_name("openSUSE: Security Advisory for texlive-filesystem (openSUSE-SU-2020:0368-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00031.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'texlive-filesystem'
  package(s) announced via the openSUSE-SU-2020:0368-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for texlive-filesystem fixes the following issues:

  Security issues fixed:

  - Changed default user for ls-R files and font cache directories to user
  nobody (bsc#1159740)

  - Switched to rm instead of safe-rm or safe-rmdir to avoid race conditions
  (bsc#1158910) .

  - Made cron script more failsafe (bsc#1150556)

  Non-security issue fixed:

  - Refreshed font map files on update (bsc#1155381)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-368=1");

  script_tag(name:"affected", value:"'texlive-filesystem' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-basic", rpm:"texlive-collection-basic~2017.135.svn41616~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-bibtexextra", rpm:"texlive-collection-bibtexextra~2017.135.svn44385~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-binextra", rpm:"texlive-collection-binextra~2017.135.svn44515~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-context", rpm:"texlive-collection-context~2017.135.svn42330~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-fontsextra", rpm:"texlive-collection-fontsextra~2017.135.svn43356~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-fontsrecommended", rpm:"texlive-collection-fontsrecommended~2017.135.svn35830~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-fontutils", rpm:"texlive-collection-fontutils~2017.135.svn37105~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-formatsextra", rpm:"texlive-collection-formatsextra~2017.135.svn44177~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-games", rpm:"texlive-collection-games~2017.135.svn42992~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-humanities", rpm:"texlive-collection-humanities~2017.135.svn42268~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langarabic", rpm:"texlive-collection-langarabic~2017.135.svn44496~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langchinese", rpm:"texlive-collection-langchinese~2017.135.svn42675~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langcjk", rpm:"texlive-collection-langcjk~2017.135.svn43009~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langcyrillic", rpm:"texlive-collection-langcyrillic~2017.135.svn44401~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langczechslovak", rpm:"texlive-collection-langczechslovak~2017.135.svn32550~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langenglish", rpm:"texlive-collection-langenglish~2017.135.svn43650~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langeuropean", rpm:"texlive-collection-langeuropean~2017.135.svn44414~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langfrench", rpm:"texlive-collection-langfrench~2017.135.svn40375~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langgerman", rpm:"texlive-collection-langgerman~2017.135.svn42045~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langgreek", rpm:"texlive-collection-langgreek~2017.135.svn44192~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langitalian", rpm:"texlive-collection-langitalian~2017.135.svn30372~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langjapanese", rpm:"texlive-collection-langjapanese~2017.135.svn44554~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langkorean", rpm:"texlive-collection-langkorean~2017.135.svn42106~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langother", rpm:"texlive-collection-langother~2017.135.svn44414~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langpolish", rpm:"texlive-collection-langpolish~2017.135.svn44371~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langportuguese", rpm:"texlive-collection-langportuguese~2017.135.svn30962~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langspanish", rpm:"texlive-collection-langspanish~2017.135.svn40587~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-latex", rpm:"texlive-collection-latex~2017.135.svn41614~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-latexextra", rpm:"texlive-collection-latexextra~2017.135.svn44544~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-latexrecommended", rpm:"texlive-collection-latexrecommended~2017.135.svn44177~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-luatex", rpm:"texlive-collection-luatex~2017.135.svn44500~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-mathscience", rpm:"texlive-collection-mathscience~2017.135.svn44396~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-metapost", rpm:"texlive-collection-metapost~2017.135.svn44297~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-music", rpm:"texlive-collection-music~2017.135.svn40561~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-pictures", rpm:"texlive-collection-pictures~2017.135.svn44395~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-plaingeneric", rpm:"texlive-collection-plaingeneric~2017.135.svn44177~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-pstricks", rpm:"texlive-collection-pstricks~2017.135.svn44460~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-publishers", rpm:"texlive-collection-publishers~2017.135.svn44485~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-xetex", rpm:"texlive-collection-xetex~2017.135.svn43059~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-devel", rpm:"texlive-devel~2017.135~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-extratools", rpm:"texlive-extratools~2017.135~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-filesystem", rpm:"texlive-filesystem~2017.135~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-basic", rpm:"texlive-scheme-basic~2017.135.svn25923~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-context", rpm:"texlive-scheme-context~2017.135.svn35799~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-full", rpm:"texlive-scheme-full~2017.135.svn44177~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-gust", rpm:"texlive-scheme-gust~2017.135.svn44177~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-infraonly", rpm:"texlive-scheme-infraonly~2017.135.svn41515~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-medium", rpm:"texlive-scheme-medium~2017.135.svn44177~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-minimal", rpm:"texlive-scheme-minimal~2017.135.svn13822~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-small", rpm:"texlive-scheme-small~2017.135.svn41825~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-tetex", rpm:"texlive-scheme-tetex~2017.135.svn44187~lp151.8.3.1", rls:"openSUSELeap15.1"))) {
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