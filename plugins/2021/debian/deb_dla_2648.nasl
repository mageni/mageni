# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892648");
  script_version("2021-05-06T03:01:47+0000");
  script_cve_id("CVE-2021-20270", "CVE-2021-27291", "CVE-2021-30152", "CVE-2021-30155", "CVE-2021-30158", "CVE-2021-30159");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-05-06 12:54:00 +0000 (Thu, 06 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-06 03:01:47 +0000 (Thu, 06 May 2021)");
  script_name("Debian LTS: Security Advisory for mediawiki (DLA-2648-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/05/msg00003.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2648-1");
  script_xref(name:"Advisory-ID", value:"DLA-2648-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/985574");
  script_xref(name:"URL", value:"https://bugs.debian.org/984664");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki'
  package(s) announced via the DLA-2648-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in mediawiki, a wiki
website engine for collaborative work.

CVE-2021-20270

An infinite loop in SMLLexer in Pygments used by mediawiki as
one if its lexers may lead to denial of service when performing
syntax highlighting of a Standard ML (SML) source file, as
demonstrated by input that only contains the 'exception' keyword.

CVE-2021-27291

pygments, the lexers used by mediawiki rely heavily on regular
expressions. Some of the regular expressions have exponential or
cubic worst-case complexity and are vulnerable to ReDoS. By
crafting malicious input, an attacker can cause a denial of service.

CVE-2021-30152

An issue was discovered in MediaWiki. When using the MediaWiki
API to 'protect' a page, a user is currently able to protect to a
higher level than they currently have permissions for.

CVE-2021-30155

An issue was discovered in MediaWiki before. ContentModelChange
does not check if a user has correct permissions to create and set
the content model of a nonexistent page.

CVE-2021-30158

An issue was discovered in MediaWiki. Blocked users are unable to
use Special:ResetTokens. This has security relevance because a
blocked user might have accidentally shared a token, or might know
that a token has been compromised, and yet is not able to block
any potential future use of the token by an unauthorized party.

CVE-2021-30159

An issue was discovered in MediaWiki. Users can bypass intended
restrictions on deleting pages in certain 'fast double move'
situations. MovePage::isValidMoveTarget() uses FOR UPDATE, but
it's only called if Title::getArticleID() returns non-zero with no
special flags. Next, MovePage::moveToInternal() will delete the
page if getArticleID(READ_LATEST) is non-zero. Therefore, if the
page is missing in the replica DB, isValidMove() will return true,
and then moveToInternal() will unconditionally delete the page if
it can be found in the master.");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1:1.27.7-1~deb9u8.

We recommend that you upgrade your mediawiki packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"mediawiki", ver:"1:1.27.7-1~deb9u8", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"mediawiki-classes", ver:"1:1.27.7-1~deb9u8", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
