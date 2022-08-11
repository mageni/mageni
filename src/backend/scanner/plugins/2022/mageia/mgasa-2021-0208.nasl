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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0208");
  script_cve_id("CVE-2021-31855");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-11 19:55:00 +0000 (Fri, 11 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0208)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0208");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0208.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28861");
  script_xref(name:"URL", value:"https://kde.org/info/security/advisory-20210429-1.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'messagelib, messagelib' package(s) announced via the MGASA-2021-0208 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Deleting an attachment of a decrypted encrypted message stored on a remote
server (e.g. an IMAP server) causes KMail to upload the decrypted content of
the message to the remote server. This is not easily noticeable by the user
because KMail does not display the decrypted content.

With a specially crafted message a user could be tricked into decrypting an
encrypted message and then deleting an attachment attached to this message.
If the attacker has access to the messages stored on the email server, then
the attacker could read the decrypted content of the encrypted message
(CVE-2021-31855).");

  script_tag(name:"affected", value:"'messagelib, messagelib' package(s) on Mageia 7, Mageia 8.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messagecomposer5", rpm:"lib64kf5messagecomposer5~19.04.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messagecore5", rpm:"lib64kf5messagecore5~19.04.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messagelib-devel", rpm:"lib64kf5messagelib-devel~19.04.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messagelist5", rpm:"lib64kf5messagelist5~19.04.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messageviewer5", rpm:"lib64kf5messageviewer5~19.04.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5mimetreeparser5", rpm:"lib64kf5mimetreeparser5~19.04.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5templateparser5", rpm:"lib64kf5templateparser5~19.04.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5webengineviewer5", rpm:"lib64kf5webengineviewer5~19.04.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messagecomposer5", rpm:"libkf5messagecomposer5~19.04.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messagecore5", rpm:"libkf5messagecore5~19.04.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messagelib-devel", rpm:"libkf5messagelib-devel~19.04.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messagelist5", rpm:"libkf5messagelist5~19.04.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messageviewer5", rpm:"libkf5messageviewer5~19.04.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5mimetreeparser5", rpm:"libkf5mimetreeparser5~19.04.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5templateparser5", rpm:"libkf5templateparser5~19.04.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5webengineviewer5", rpm:"libkf5webengineviewer5~19.04.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"messagelib", rpm:"messagelib~19.04.0~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messagecomposer5", rpm:"lib64kf5messagecomposer5~20.12.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messagecore5", rpm:"lib64kf5messagecore5~20.12.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messagelib-devel", rpm:"lib64kf5messagelib-devel~20.12.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messagelist5", rpm:"lib64kf5messagelist5~20.12.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5messageviewer5", rpm:"lib64kf5messageviewer5~20.12.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5mimetreeparser5", rpm:"lib64kf5mimetreeparser5~20.12.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5templateparser5", rpm:"lib64kf5templateparser5~20.12.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kf5webengineviewer5", rpm:"lib64kf5webengineviewer5~20.12.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messagecomposer5", rpm:"libkf5messagecomposer5~20.12.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messagecore5", rpm:"libkf5messagecore5~20.12.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messagelib-devel", rpm:"libkf5messagelib-devel~20.12.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messagelist5", rpm:"libkf5messagelist5~20.12.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5messageviewer5", rpm:"libkf5messageviewer5~20.12.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5mimetreeparser5", rpm:"libkf5mimetreeparser5~20.12.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5templateparser5", rpm:"libkf5templateparser5~20.12.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkf5webengineviewer5", rpm:"libkf5webengineviewer5~20.12.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"messagelib", rpm:"messagelib~20.12.0~1.1.mga8", rls:"MAGEIA8"))) {
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
