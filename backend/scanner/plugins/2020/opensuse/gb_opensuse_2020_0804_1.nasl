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
  script_oid("1.3.6.1.4.1.25623.1.0.853205");
  script_version("2020-06-24T03:42:18+0000");
  script_cve_id("CVE-2020-8016", "CVE-2020-8017");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-06-24 03:42:18 +0000 (Wed, 24 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-14 03:00:54 +0000 (Sun, 14 Jun 2020)");
  script_name("openSUSE: Security Advisory for texlive-filesystem (openSUSE-SU-2020:0804-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0804-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00021.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'texlive-filesystem'
  package(s) announced via the openSUSE-SU-2020:0804-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for texlive-filesystem fixes the following issues:

  Security issues fixed:

  - CVE-2020-8016: Fixed a race condition in the spec file (bsc#1159740).

  - CVE-2020-8017: Fixed a race condition on a cron job (bsc#1158910).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-804=1");

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

  if(!isnull(res = isrpmvuln(pkg:"libkpathsea6", rpm:"libkpathsea6~6.2.3~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkpathsea6-debuginfo", rpm:"libkpathsea6-debuginfo~6.2.3~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libptexenc1", rpm:"libptexenc1~1.3.5~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libptexenc1-debuginfo", rpm:"libptexenc1-debuginfo~1.3.5~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsynctex1", rpm:"libsynctex1~1.18~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsynctex1-debuginfo", rpm:"libsynctex1-debuginfo~1.18~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtexlua52-5", rpm:"libtexlua52-5~5.2.4~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtexlua52-5-debuginfo", rpm:"libtexlua52-5-debuginfo~5.2.4~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtexluajit2", rpm:"libtexluajit2~2.1.0beta2~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtexluajit2-debuginfo", rpm:"libtexluajit2-debuginfo~2.1.0beta2~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive", rpm:"texlive~2017.20170520~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-a2ping-bin", rpm:"texlive-a2ping-bin~2017.20170520.svn27321~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-accfonts-bin", rpm:"texlive-accfonts-bin~2017.20170520.svn12688~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-adhocfilelist-bin", rpm:"texlive-adhocfilelist-bin~2017.20170520.svn28038~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-afm2pl-bin", rpm:"texlive-afm2pl-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-afm2pl-bin-debuginfo", rpm:"texlive-afm2pl-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-aleph-bin", rpm:"texlive-aleph-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-aleph-bin-debuginfo", rpm:"texlive-aleph-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-amstex-bin", rpm:"texlive-amstex-bin~2017.20170520.svn3006~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-arara-bin", rpm:"texlive-arara-bin~2017.20170520.svn29036~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-asymptote-bin", rpm:"texlive-asymptote-bin~2017.20170520.svn43843~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-asymptote-bin-debuginfo", rpm:"texlive-asymptote-bin-debuginfo~2017.20170520.svn43843~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-authorindex-bin", rpm:"texlive-authorindex-bin~2017.20170520.svn18790~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-autosp-bin", rpm:"texlive-autosp-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-autosp-bin-debuginfo", rpm:"texlive-autosp-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibexport-bin", rpm:"texlive-bibexport-bin~2017.20170520.svn16219~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtex-bin", rpm:"texlive-bibtex-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtex-bin-debuginfo", rpm:"texlive-bibtex-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtex8-bin", rpm:"texlive-bibtex8-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtex8-bin-debuginfo", rpm:"texlive-bibtex8-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtexu-bin", rpm:"texlive-bibtexu-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bibtexu-bin-debuginfo", rpm:"texlive-bibtexu-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bin-devel", rpm:"texlive-bin-devel~2017.20170520~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-bundledoc-bin", rpm:"texlive-bundledoc-bin~2017.20170520.svn17794~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cachepic-bin", rpm:"texlive-cachepic-bin~2017.20170520.svn15543~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-checkcites-bin", rpm:"texlive-checkcites-bin~2017.20170520.svn25623~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-checklistings-bin", rpm:"texlive-checklistings-bin~2017.20170520.svn38300~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-chktex-bin", rpm:"texlive-chktex-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-chktex-bin-debuginfo", rpm:"texlive-chktex-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cjk-gs-integrate-bin", rpm:"texlive-cjk-gs-integrate-bin~2017.20170520.svn37223~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cjkutils-bin", rpm:"texlive-cjkutils-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cjkutils-bin-debuginfo", rpm:"texlive-cjkutils-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-context-bin", rpm:"texlive-context-bin~2017.20170520.svn34112~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-convbkmk-bin", rpm:"texlive-convbkmk-bin~2017.20170520.svn30408~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-crossrefware-bin", rpm:"texlive-crossrefware-bin~2017.20170520.svn43866~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cslatex-bin", rpm:"texlive-cslatex-bin~2017.20170520.svn3006~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-csplain-bin", rpm:"texlive-csplain-bin~2017.20170520.svn33902~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctanify-bin", rpm:"texlive-ctanify-bin~2017.20170520.svn24061~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctanupload-bin", rpm:"texlive-ctanupload-bin~2017.20170520.svn23866~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctie-bin", rpm:"texlive-ctie-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ctie-bin-debuginfo", rpm:"texlive-ctie-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cweb-bin", rpm:"texlive-cweb-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cweb-bin-debuginfo", rpm:"texlive-cweb-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-cyrillic-bin-bin", rpm:"texlive-cyrillic-bin-bin~2017.20170520.svn29741~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-de-macro-bin", rpm:"texlive-de-macro-bin~2017.20170520.svn17399~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-debuginfo", rpm:"texlive-debuginfo~2017.20170520~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-debugsource", rpm:"texlive-debugsource~2017.20170520~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-detex-bin", rpm:"texlive-detex-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-detex-bin-debuginfo", rpm:"texlive-detex-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dosepsbin-bin", rpm:"texlive-dosepsbin-bin~2017.20170520.svn24759~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dtl-bin", rpm:"texlive-dtl-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dtl-bin-debuginfo", rpm:"texlive-dtl-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dtxgen-bin", rpm:"texlive-dtxgen-bin~2017.20170520.svn29031~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviasm-bin", rpm:"texlive-dviasm-bin~2017.20170520.svn8329~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvicopy-bin", rpm:"texlive-dvicopy-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvicopy-bin-debuginfo", rpm:"texlive-dvicopy-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvidvi-bin", rpm:"texlive-dvidvi-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvidvi-bin-debuginfo", rpm:"texlive-dvidvi-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviinfox-bin", rpm:"texlive-dviinfox-bin~2017.20170520.svn44515~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviljk-bin", rpm:"texlive-dviljk-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dviljk-bin-debuginfo", rpm:"texlive-dviljk-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipdfmx-bin", rpm:"texlive-dvipdfmx-bin~2017.20170520.svn40273~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipng-bin", rpm:"texlive-dvipng-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipng-bin-debuginfo", rpm:"texlive-dvipng-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipos-bin", rpm:"texlive-dvipos-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvipos-bin-debuginfo", rpm:"texlive-dvipos-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvips-bin", rpm:"texlive-dvips-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvips-bin-debuginfo", rpm:"texlive-dvips-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvisvgm-bin", rpm:"texlive-dvisvgm-bin~2017.20170520.svn40987~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-dvisvgm-bin-debuginfo", rpm:"texlive-dvisvgm-bin-debuginfo~2017.20170520.svn40987~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ebong-bin", rpm:"texlive-ebong-bin~2017.20170520.svn21000~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-eplain-bin", rpm:"texlive-eplain-bin~2017.20170520.svn3006~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-epspdf-bin", rpm:"texlive-epspdf-bin~2017.20170520.svn29050~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-epstopdf-bin", rpm:"texlive-epstopdf-bin~2017.20170520.svn18336~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-exceltex-bin", rpm:"texlive-exceltex-bin~2017.20170520.svn25860~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fig4latex-bin", rpm:"texlive-fig4latex-bin~2017.20170520.svn14752~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-findhyph-bin", rpm:"texlive-findhyph-bin~2017.20170520.svn14758~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fontinst-bin", rpm:"texlive-fontinst-bin~2017.20170520.svn29741~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fontools-bin", rpm:"texlive-fontools-bin~2017.20170520.svn25997~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fontware-bin", rpm:"texlive-fontware-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fontware-bin-debuginfo", rpm:"texlive-fontware-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-fragmaster-bin", rpm:"texlive-fragmaster-bin~2017.20170520.svn13663~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-getmap-bin", rpm:"texlive-getmap-bin~2017.20170520.svn34971~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-glossaries-bin", rpm:"texlive-glossaries-bin~2017.20170520.svn37813~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-gregoriotex-bin", rpm:"texlive-gregoriotex-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-gregoriotex-bin-debuginfo", rpm:"texlive-gregoriotex-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-gsftopk-bin", rpm:"texlive-gsftopk-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-gsftopk-bin-debuginfo", rpm:"texlive-gsftopk-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-jadetex-bin", rpm:"texlive-jadetex-bin~2017.20170520.svn3006~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-kotex-utils-bin", rpm:"texlive-kotex-utils-bin~2017.20170520.svn32101~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-kpathsea-bin", rpm:"texlive-kpathsea-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-kpathsea-bin-debuginfo", rpm:"texlive-kpathsea-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-kpathsea-devel", rpm:"texlive-kpathsea-devel~6.2.3~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lacheck-bin", rpm:"texlive-lacheck-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lacheck-bin-debuginfo", rpm:"texlive-lacheck-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex-bin-bin", rpm:"texlive-latex-bin-bin~2017.20170520.svn14050~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex-git-log-bin", rpm:"texlive-latex-git-log-bin~2017.20170520.svn30983~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex-papersize-bin", rpm:"texlive-latex-papersize-bin~2017.20170520.svn42296~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex2man-bin", rpm:"texlive-latex2man-bin~2017.20170520.svn13663~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latex2nemeth-bin", rpm:"texlive-latex2nemeth-bin~2017.20170520.svn42300~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latexdiff-bin", rpm:"texlive-latexdiff-bin~2017.20170520.svn16420~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latexfileversion-bin", rpm:"texlive-latexfileversion-bin~2017.20170520.svn25012~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latexindent-bin", rpm:"texlive-latexindent-bin~2017.20170520.svn32150~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latexmk-bin", rpm:"texlive-latexmk-bin~2017.20170520.svn10937~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-latexpand-bin", rpm:"texlive-latexpand-bin~2017.20170520.svn27025~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lcdftypetools-bin", rpm:"texlive-lcdftypetools-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lcdftypetools-bin-debuginfo", rpm:"texlive-lcdftypetools-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lilyglyphs-bin", rpm:"texlive-lilyglyphs-bin~2017.20170520.svn31696~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-listbib-bin", rpm:"texlive-listbib-bin~2017.20170520.svn26126~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-listings-ext-bin", rpm:"texlive-listings-ext-bin~2017.20170520.svn15093~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lollipop-bin", rpm:"texlive-lollipop-bin~2017.20170520.svn41465~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ltxfileinfo-bin", rpm:"texlive-ltxfileinfo-bin~2017.20170520.svn29005~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ltximg-bin", rpm:"texlive-ltximg-bin~2017.20170520.svn32346~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lua2dox-bin", rpm:"texlive-lua2dox-bin~2017.20170520.svn29053~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luaotfload-bin", rpm:"texlive-luaotfload-bin~2017.20170520.svn34647~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luatex-bin", rpm:"texlive-luatex-bin~2017.20170520.svn44549~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-luatex-bin-debuginfo", rpm:"texlive-luatex-bin-debuginfo~2017.20170520.svn44549~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-lwarp-bin", rpm:"texlive-lwarp-bin~2017.20170520.svn43292~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-m-tx-bin", rpm:"texlive-m-tx-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-m-tx-bin-debuginfo", rpm:"texlive-m-tx-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-make4ht-bin", rpm:"texlive-make4ht-bin~2017.20170520.svn37750~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-makedtx-bin", rpm:"texlive-makedtx-bin~2017.20170520.svn38769~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-makeindex-bin", rpm:"texlive-makeindex-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-makeindex-bin-debuginfo", rpm:"texlive-makeindex-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-match_parens-bin", rpm:"texlive-match_parens-bin~2017.20170520.svn23500~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mathspic-bin", rpm:"texlive-mathspic-bin~2017.20170520.svn23661~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-metafont-bin", rpm:"texlive-metafont-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-metafont-bin-debuginfo", rpm:"texlive-metafont-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-metapost-bin", rpm:"texlive-metapost-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-metapost-bin-debuginfo", rpm:"texlive-metapost-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mex-bin", rpm:"texlive-mex-bin~2017.20170520.svn3006~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mf2pt1-bin", rpm:"texlive-mf2pt1-bin~2017.20170520.svn23406~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mflua-bin", rpm:"texlive-mflua-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mflua-bin-debuginfo", rpm:"texlive-mflua-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mfware-bin", rpm:"texlive-mfware-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mfware-bin-debuginfo", rpm:"texlive-mfware-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mkgrkindex-bin", rpm:"texlive-mkgrkindex-bin~2017.20170520.svn14428~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mkjobtexmf-bin", rpm:"texlive-mkjobtexmf-bin~2017.20170520.svn8457~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mkpic-bin", rpm:"texlive-mkpic-bin~2017.20170520.svn33688~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mltex-bin", rpm:"texlive-mltex-bin~2017.20170520.svn3006~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-mptopdf-bin", rpm:"texlive-mptopdf-bin~2017.20170520.svn18674~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-multibibliography-bin", rpm:"texlive-multibibliography-bin~2017.20170520.svn30534~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-musixtex-bin", rpm:"texlive-musixtex-bin~2017.20170520.svn37026~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-musixtnt-bin", rpm:"texlive-musixtnt-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-musixtnt-bin-debuginfo", rpm:"texlive-musixtnt-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-omegaware-bin", rpm:"texlive-omegaware-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-omegaware-bin-debuginfo", rpm:"texlive-omegaware-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-patgen-bin", rpm:"texlive-patgen-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-patgen-bin-debuginfo", rpm:"texlive-patgen-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pax-bin", rpm:"texlive-pax-bin~2017.20170520.svn10843~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdfbook2-bin", rpm:"texlive-pdfbook2-bin~2017.20170520.svn37537~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdfcrop-bin", rpm:"texlive-pdfcrop-bin~2017.20170520.svn14387~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdfjam-bin", rpm:"texlive-pdfjam-bin~2017.20170520.svn17868~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdflatexpicscale-bin", rpm:"texlive-pdflatexpicscale-bin~2017.20170520.svn41779~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdftex-bin", rpm:"texlive-pdftex-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdftex-bin-debuginfo", rpm:"texlive-pdftex-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdftools-bin", rpm:"texlive-pdftools-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdftools-bin-debuginfo", rpm:"texlive-pdftools-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pdfxup-bin", rpm:"texlive-pdfxup-bin~2017.20170520.svn40690~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pedigree-perl-bin", rpm:"texlive-pedigree-perl-bin~2017.20170520.svn25962~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-perltex-bin", rpm:"texlive-perltex-bin~2017.20170520.svn16181~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-petri-nets-bin", rpm:"texlive-petri-nets-bin~2017.20170520.svn39165~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pfarrei-bin", rpm:"texlive-pfarrei-bin~2017.20170520.svn29348~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pkfix-bin", rpm:"texlive-pkfix-bin~2017.20170520.svn13364~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pkfix-helper-bin", rpm:"texlive-pkfix-helper-bin~2017.20170520.svn13663~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-platex-bin", rpm:"texlive-platex-bin~2017.20170520.svn22859~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pmx-bin", rpm:"texlive-pmx-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pmx-bin-debuginfo", rpm:"texlive-pmx-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pmxchords-bin", rpm:"texlive-pmxchords-bin~2017.20170520.svn32405~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ps2pk-bin", rpm:"texlive-ps2pk-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ps2pk-bin-debuginfo", rpm:"texlive-ps2pk-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pst-pdf-bin", rpm:"texlive-pst-pdf-bin~2017.20170520.svn7838~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pst2pdf-bin", rpm:"texlive-pst2pdf-bin~2017.20170520.svn29333~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pstools-bin", rpm:"texlive-pstools-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pstools-bin-debuginfo", rpm:"texlive-pstools-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ptex-bin", rpm:"texlive-ptex-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ptex-bin-debuginfo", rpm:"texlive-ptex-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ptex-fontmaps-bin", rpm:"texlive-ptex-fontmaps-bin~2017.20170520.svn44206~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ptex2pdf-bin", rpm:"texlive-ptex2pdf-bin~2017.20170520.svn29335~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ptexenc-devel", rpm:"texlive-ptexenc-devel~1.3.5~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-purifyeps-bin", rpm:"texlive-purifyeps-bin~2017.20170520.svn13663~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pygmentex-bin", rpm:"texlive-pygmentex-bin~2017.20170520.svn34996~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-pythontex-bin", rpm:"texlive-pythontex-bin~2017.20170520.svn31638~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-rubik-bin", rpm:"texlive-rubik-bin~2017.20170520.svn32919~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-seetexk-bin", rpm:"texlive-seetexk-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-seetexk-bin-debuginfo", rpm:"texlive-seetexk-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-splitindex-bin", rpm:"texlive-splitindex-bin~2017.20170520.svn29688~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-srcredact-bin", rpm:"texlive-srcredact-bin~2017.20170520.svn38710~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-sty2dtx-bin", rpm:"texlive-sty2dtx-bin~2017.20170520.svn21215~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-svn-multi-bin", rpm:"texlive-svn-multi-bin~2017.20170520.svn13663~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-synctex-bin", rpm:"texlive-synctex-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-synctex-bin-debuginfo", rpm:"texlive-synctex-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-synctex-devel", rpm:"texlive-synctex-devel~1.18~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tetex-bin", rpm:"texlive-tetex-bin~2017.20170520.svn43957~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex-bin", rpm:"texlive-tex-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex-bin-debuginfo", rpm:"texlive-tex-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex4ebook-bin", rpm:"texlive-tex4ebook-bin~2017.20170520.svn37771~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex4ht-bin", rpm:"texlive-tex4ht-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tex4ht-bin-debuginfo", rpm:"texlive-tex4ht-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texconfig-bin", rpm:"texlive-texconfig-bin~2017.20170520.svn29741~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texcount-bin", rpm:"texlive-texcount-bin~2017.20170520.svn13013~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texdef-bin", rpm:"texlive-texdef-bin~2017.20170520.svn21802~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texdiff-bin", rpm:"texlive-texdiff-bin~2017.20170520.svn15506~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texdirflatten-bin", rpm:"texlive-texdirflatten-bin~2017.20170520.svn12782~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texdoc-bin", rpm:"texlive-texdoc-bin~2017.20170520.svn29741~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texfot-bin", rpm:"texlive-texfot-bin~2017.20170520.svn33155~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texliveonfly-bin", rpm:"texlive-texliveonfly-bin~2017.20170520.svn24062~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texloganalyser-bin", rpm:"texlive-texloganalyser-bin~2017.20170520.svn13663~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texlua-devel", rpm:"texlive-texlua-devel~5.2.4~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texluajit-devel", rpm:"texlive-texluajit-devel~2.1.0beta2~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texosquery-bin", rpm:"texlive-texosquery-bin~2017.20170520.svn43596~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texsis-bin", rpm:"texlive-texsis-bin~2017.20170520.svn3006~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texware-bin", rpm:"texlive-texware-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-texware-bin-debuginfo", rpm:"texlive-texware-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-thumbpdf-bin", rpm:"texlive-thumbpdf-bin~2017.20170520.svn6898~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tie-bin", rpm:"texlive-tie-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tie-bin-debuginfo", rpm:"texlive-tie-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-tpic2pdftex-bin", rpm:"texlive-tpic2pdftex-bin~2017.20170520.svn29741~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ttfutils-bin", rpm:"texlive-ttfutils-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ttfutils-bin-debuginfo", rpm:"texlive-ttfutils-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-typeoutfileinfo-bin", rpm:"texlive-typeoutfileinfo-bin~2017.20170520.svn25648~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-ulqda-bin", rpm:"texlive-ulqda-bin~2017.20170520.svn13663~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-uplatex-bin", rpm:"texlive-uplatex-bin~2017.20170520.svn26326~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-uptex-bin", rpm:"texlive-uptex-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-uptex-bin-debuginfo", rpm:"texlive-uptex-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-urlbst-bin", rpm:"texlive-urlbst-bin~2017.20170520.svn23262~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-velthuis-bin", rpm:"texlive-velthuis-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-velthuis-bin-debuginfo", rpm:"texlive-velthuis-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-vlna-bin", rpm:"texlive-vlna-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-vlna-bin-debuginfo", rpm:"texlive-vlna-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-vpe-bin", rpm:"texlive-vpe-bin~2017.20170520.svn6897~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-web-bin", rpm:"texlive-web-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-web-bin-debuginfo", rpm:"texlive-web-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xdvi-bin", rpm:"texlive-xdvi-bin~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xdvi-bin-debuginfo", rpm:"texlive-xdvi-bin-debuginfo~2017.20170520.svn44143~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xetex-bin", rpm:"texlive-xetex-bin~2017.20170520.svn44361~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xetex-bin-debuginfo", rpm:"texlive-xetex-bin-debuginfo~2017.20170520.svn44361~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-xmltex-bin", rpm:"texlive-xmltex-bin~2017.20170520.svn3006~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-yplan-bin", rpm:"texlive-yplan-bin~2017.20170520.svn34398~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-biber", rpm:"perl-biber~2017.20170520.svn30357~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-biber-bin", rpm:"texlive-biber-bin~2017.20170520.svn42679~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-basic", rpm:"texlive-collection-basic~2017.135.svn41616~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-bibtexextra", rpm:"texlive-collection-bibtexextra~2017.135.svn44385~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-binextra", rpm:"texlive-collection-binextra~2017.135.svn44515~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-context", rpm:"texlive-collection-context~2017.135.svn42330~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-fontsextra", rpm:"texlive-collection-fontsextra~2017.135.svn43356~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-fontsrecommended", rpm:"texlive-collection-fontsrecommended~2017.135.svn35830~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-fontutils", rpm:"texlive-collection-fontutils~2017.135.svn37105~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-formatsextra", rpm:"texlive-collection-formatsextra~2017.135.svn44177~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-games", rpm:"texlive-collection-games~2017.135.svn42992~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-humanities", rpm:"texlive-collection-humanities~2017.135.svn42268~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langarabic", rpm:"texlive-collection-langarabic~2017.135.svn44496~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langchinese", rpm:"texlive-collection-langchinese~2017.135.svn42675~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langcjk", rpm:"texlive-collection-langcjk~2017.135.svn43009~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langcyrillic", rpm:"texlive-collection-langcyrillic~2017.135.svn44401~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langczechslovak", rpm:"texlive-collection-langczechslovak~2017.135.svn32550~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langenglish", rpm:"texlive-collection-langenglish~2017.135.svn43650~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langeuropean", rpm:"texlive-collection-langeuropean~2017.135.svn44414~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langfrench", rpm:"texlive-collection-langfrench~2017.135.svn40375~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langgerman", rpm:"texlive-collection-langgerman~2017.135.svn42045~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langgreek", rpm:"texlive-collection-langgreek~2017.135.svn44192~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langitalian", rpm:"texlive-collection-langitalian~2017.135.svn30372~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langjapanese", rpm:"texlive-collection-langjapanese~2017.135.svn44554~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langkorean", rpm:"texlive-collection-langkorean~2017.135.svn42106~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langother", rpm:"texlive-collection-langother~2017.135.svn44414~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langpolish", rpm:"texlive-collection-langpolish~2017.135.svn44371~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langportuguese", rpm:"texlive-collection-langportuguese~2017.135.svn30962~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-langspanish", rpm:"texlive-collection-langspanish~2017.135.svn40587~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-latex", rpm:"texlive-collection-latex~2017.135.svn41614~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-latexextra", rpm:"texlive-collection-latexextra~2017.135.svn44544~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-latexrecommended", rpm:"texlive-collection-latexrecommended~2017.135.svn44177~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-luatex", rpm:"texlive-collection-luatex~2017.135.svn44500~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-mathscience", rpm:"texlive-collection-mathscience~2017.135.svn44396~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-metapost", rpm:"texlive-collection-metapost~2017.135.svn44297~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-music", rpm:"texlive-collection-music~2017.135.svn40561~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-pictures", rpm:"texlive-collection-pictures~2017.135.svn44395~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-plaingeneric", rpm:"texlive-collection-plaingeneric~2017.135.svn44177~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-pstricks", rpm:"texlive-collection-pstricks~2017.135.svn44460~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-publishers", rpm:"texlive-collection-publishers~2017.135.svn44485~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-collection-xetex", rpm:"texlive-collection-xetex~2017.135.svn43059~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-devel", rpm:"texlive-devel~2017.135~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-diadia-bin", rpm:"texlive-diadia-bin~2017.20170520.svn37645~lp151.12.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-extratools", rpm:"texlive-extratools~2017.135~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-filesystem", rpm:"texlive-filesystem~2017.135~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-basic", rpm:"texlive-scheme-basic~2017.135.svn25923~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-context", rpm:"texlive-scheme-context~2017.135.svn35799~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-full", rpm:"texlive-scheme-full~2017.135.svn44177~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-gust", rpm:"texlive-scheme-gust~2017.135.svn44177~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-infraonly", rpm:"texlive-scheme-infraonly~2017.135.svn41515~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-medium", rpm:"texlive-scheme-medium~2017.135.svn44177~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-minimal", rpm:"texlive-scheme-minimal~2017.135.svn13822~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-small", rpm:"texlive-scheme-small~2017.135.svn41825~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"texlive-scheme-tetex", rpm:"texlive-scheme-tetex~2017.135.svn44187~lp151.8.6.1", rls:"openSUSELeap15.1"))) {
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