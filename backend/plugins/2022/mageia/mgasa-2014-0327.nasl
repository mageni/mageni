# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0327");
  script_cve_id("CVE-2014-5033");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-10-16 07:22:00 +0000 (Thu, 16 Oct 2014)");

  script_name("Mageia: Security Advisory (MGASA-2014-0327)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0327");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0327.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13826");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13792");
  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20140730-1.txt");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=864716");
  script_xref(name:"URL", value:"https://git.reviewboard.kde.org/r/111371/");
  script_xref(name:"URL", value:"https://bugs.kde.org/show_bug.cgi?id=324954");
  script_xref(name:"URL", value:"https://bugs.kde.org/show_bug.cgi?id=292378");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12982");
  script_xref(name:"URL", value:"https://bugs.kde.org/show_bug.cgi?id=335001");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13555");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13559");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdelibs4' package(s) announced via the MGASA-2014-0327 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes a security vulnerability in the polkit authentication
backend of kdelibs (CVE-2014-5033) (mga#13792), and fixes some
additional issues:
 - duplicate targets in PythonMacros.cmake (reviewboard kde 111371),
 - kded4 leak sockets in NetworkInterface::isWireless() (bko#324954),
 - media type application/x-konsole is unsupported (bko#292378),
 - pure Qt applications (like VLC) that get the kdelibs file dialog
 are not properly translated (mga#12982),
 - meinproc4 doesn't substitute entity with libxml2 fixed for
 CVE-2014-0191 (bko#335001, mga#13555, mga#13559),");

  script_tag(name:"affected", value:"'kdelibs4' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4", rpm:"kdelibs4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4-core", rpm:"kdelibs4-core~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4-devel", rpm:"kdelibs4-devel~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs4-handbooks", rpm:"kdelibs4-handbooks~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kcmutils4", rpm:"lib64kcmutils4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kde3support4", rpm:"lib64kde3support4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdeclarative5", rpm:"lib64kdeclarative5~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdecore5", rpm:"lib64kdecore5~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdefakes5", rpm:"lib64kdefakes5~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdesu5", rpm:"lib64kdesu5~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdeui5", rpm:"lib64kdeui5~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdewebkit5", rpm:"lib64kdewebkit5~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kdnssd4", rpm:"lib64kdnssd4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kemoticons4", rpm:"lib64kemoticons4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kfile4", rpm:"lib64kfile4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64khtml5", rpm:"lib64khtml5~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kidletime4", rpm:"lib64kidletime4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kimproxy4", rpm:"lib64kimproxy4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kio5", rpm:"lib64kio5~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kjs4", rpm:"lib64kjs4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kjsapi4", rpm:"lib64kjsapi4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kjsembed4", rpm:"lib64kjsembed4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kmediaplayer4", rpm:"lib64kmediaplayer4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64knewstuff2_4", rpm:"lib64knewstuff2_4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64knewstuff3_4", rpm:"lib64knewstuff3_4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64knotifyconfig4", rpm:"lib64knotifyconfig4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kntlm4", rpm:"lib64kntlm4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kparts4", rpm:"lib64kparts4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kprintutils4", rpm:"lib64kprintutils4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kpty4", rpm:"lib64kpty4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64krosscore4", rpm:"lib64krosscore4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64krossui4", rpm:"lib64krossui4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ktexteditor4", rpm:"lib64ktexteditor4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kunitconversion4", rpm:"lib64kunitconversion4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kunittest4", rpm:"lib64kunittest4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kutils4", rpm:"lib64kutils4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nepomuk4", rpm:"lib64nepomuk4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nepomukquery4", rpm:"lib64nepomukquery4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nepomukutils4", rpm:"lib64nepomukutils4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64plasma3", rpm:"lib64plasma3~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64solid4", rpm:"lib64solid4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64threadweaver4", rpm:"lib64threadweaver4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkcmutils4", rpm:"libkcmutils4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkde3support4", rpm:"libkde3support4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdeclarative5", rpm:"libkdeclarative5~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdecore5", rpm:"libkdecore5~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdefakes5", rpm:"libkdefakes5~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdesu5", rpm:"libkdesu5~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdeui5", rpm:"libkdeui5~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdewebkit5", rpm:"libkdewebkit5~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkdnssd4", rpm:"libkdnssd4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkemoticons4", rpm:"libkemoticons4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkfile4", rpm:"libkfile4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkhtml5", rpm:"libkhtml5~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkidletime4", rpm:"libkidletime4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkimproxy4", rpm:"libkimproxy4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkio5", rpm:"libkio5~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkjs4", rpm:"libkjs4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkjsapi4", rpm:"libkjsapi4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkjsembed4", rpm:"libkjsembed4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkmediaplayer4", rpm:"libkmediaplayer4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libknewstuff2_4", rpm:"libknewstuff2_4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libknewstuff3_4", rpm:"libknewstuff3_4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libknotifyconfig4", rpm:"libknotifyconfig4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkntlm4", rpm:"libkntlm4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkparts4", rpm:"libkparts4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkprintutils4", rpm:"libkprintutils4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkpty4", rpm:"libkpty4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrosscore4", rpm:"libkrosscore4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrossui4", rpm:"libkrossui4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libktexteditor4", rpm:"libktexteditor4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkunitconversion4", rpm:"libkunitconversion4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkunittest4", rpm:"libkunittest4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkutils4", rpm:"libkutils4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnepomuk4", rpm:"libnepomuk4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnepomukquery4", rpm:"libnepomukquery4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnepomukutils4", rpm:"libnepomukutils4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libplasma3", rpm:"libplasma3~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsolid4", rpm:"libsolid4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libthreadweaver4", rpm:"libthreadweaver4~4.10.5~1.2.mga3", rls:"MAGEIA3"))) {
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
