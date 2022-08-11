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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0142");
  script_cve_id("CVE-2015-2931", "CVE-2015-2932", "CVE-2015-2933", "CVE-2015-2934", "CVE-2015-2935", "CVE-2015-2936", "CVE-2015-2937", "CVE-2015-2938", "CVE-2015-2939", "CVE-2015-2940");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 18:10:00 +0000 (Wed, 07 Dec 2016)");

  script_name("Mageia: Security Advisory (MGASA-2015-0142)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0142");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0142.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15606");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2015-March/000175.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/04/07/3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki' package(s) announced via the MGASA-2015-0142 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated mediawiki packages fix security vulnerabilities:

In MediaWiki before 1.23.9, one could circumvent the SVG MIME blacklist for
embedded resources. This allowed an attacker to embed JavaScript in the SVG
(CVE-2015-2931).

In MediaWiki before 1.23.9, the SVG filter to prevent injecting JavaScript
using animate elements was incorrect (CVE-2015-2932).

In MediaWiki before 1.23.9, a stored XSS vulnerability exists due to the way
attributes were expanded in MediaWiki's Html class, in combination with
LanguageConverter substitutions (CVE-2015-2933).

In MediaWiki before 1.23.9, MediaWiki's SVG filtering could be bypassed with
entity encoding under the Zend interpreter. This could be used to inject
JavaScript (CVE-2015-2934).

In MediaWiki before 1.23.9, one could bypass the style filtering for SVG
files to load external resources. This could violate the anonymity of users
viewing the SVG (CVE-2015-2935).

In MediaWiki before 1.23.9, MediaWiki versions using PBKDF2 for password
hashing (not the default for 1.23) are vulnerable to DoS attacks using
extremely long passwords (CVE-2015-2936).

In MediaWiki before 1.23.9, MediaWiki is vulnerable to 'Quadratic Blowup'
DoS attacks, under both HHVM and Zend PHP (CVE-2015-2937).

In MediaWiki before 1.23.9, the MediaWiki feature allowing a user to preview
another user's custom JavaScript could be abused for privilege escalation
(CVE-2015-2938).

In MediaWiki before 1.23.9, function names were not sanitized in Lua error
backtraces, which could lead to XSS (CVE-2015-2939).

In MediaWiki before 1.23.9, the CheckUser extension did not prevent CSRF
attacks on the form allowing checkusers to look up sensitive information
about other users. Since the use of CheckUser is logged, the CSRF could be
abused to defame a trusted user or flood the logs with noise (CVE-2015-2940).

The mediawiki package has been updated to version 1.23.9, fixing these issues
and other bugs.");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.23.9~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-mysql", rpm:"mediawiki-mysql~1.23.9~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-pgsql", rpm:"mediawiki-pgsql~1.23.9~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-sqlite", rpm:"mediawiki-sqlite~1.23.9~1.mga4", rls:"MAGEIA4"))) {
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
