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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0218");
  script_cve_id("CVE-2021-20270", "CVE-2021-27291", "CVE-2021-30152", "CVE-2021-30155", "CVE-2021-30158", "CVE-2021-30159");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-06 23:15:00 +0000 (Thu, 06 May 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0218)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0218");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0218.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28883");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4889");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2021-April/000272.html");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2021-April/000273.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki, mediawiki' package(s) announced via the MGASA-2021-0218 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An infinite loop in SMLLexer in Pygments versions 1.5 to 2.7.3 may lead to denial of service when performing syntax highlighting of a Standard ML (SML) source file, as demonstrated by input that only contains the 'exception' keyword (CVE-2021-20270).

A deadlock vulnerability was found in 'github.com/containers/storage' in versions before 1.28.1. When a container image is processed, each layer is unpacked using `tar`. If one of those layers is not a valid `tar` archive this causes an error leading to an unexpected situation where the code indefinitely waits for the tar unpacked stream, which never finishes. An attacker could use this vulnerability to craft a malicious image, which when downloaded and stored by an application using containers/storage, would then cause a deadlock leading to a Denial of Service (DoS) (CVE-2021-27291).

An issue was discovered in MediaWiki before 1.31.13 and 1.32.x through 1.35.x before 1.35.2. When using the MediaWiki API to 'protect' a page, a user is currently able to protect to a higher level than they currently have permissions for (CVE-2021-30152).

An issue was discovered in MediaWiki before 1.31.12 and 1.32.x through 1.35.x before 1.35.2. ContentModelChange does not check if a user has correct permissions to create and set the content model of a nonexistent page (CVE-2021-30155).

An issue was discovered in MediaWiki before 1.31.12 and 1.32.x through 1.35.x before 1.35.2. Blocked users are unable to use Special:ResetTokens. This has security relevance because a blocked user might have accidentally shared a token, or might know that a token has been compromised, and yet is not able to block any potential future use of the token by an unauthorized party
(CVE-2021-30158).

An issue was discovered in MediaWiki before 1.31.12 and 1.32.x through 1.35.x before 1.35.2. Users can bypass intended restrictions on deleting pages in certain 'fast double move' situations. MovePage::isValidMoveTarget() uses FOR UPDATE, but it's only called if Title::getArticleID() returns non-zero with no special flags. Next, MovePage::moveToInternal() will delete the page if getArticleID(READ_LATEST) is non-zero. Therefore, if the page is missing in the replica DB, isValidMove() will return true, and then moveToInternal() will unconditionally delete the page if it can be found in the master (CVE-2021-30159).");

  script_tag(name:"affected", value:"'mediawiki, mediawiki' package(s) on Mageia 7, Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.31.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-mysql", rpm:"mediawiki-mysql~1.31.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-pgsql", rpm:"mediawiki-pgsql~1.31.14~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-sqlite", rpm:"mediawiki-sqlite~1.31.14~1.mga7", rls:"MAGEIA7"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.35.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-mysql", rpm:"mediawiki-mysql~1.35.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-pgsql", rpm:"mediawiki-pgsql~1.35.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-sqlite", rpm:"mediawiki-sqlite~1.35.2~1.mga8", rls:"MAGEIA8"))) {
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
