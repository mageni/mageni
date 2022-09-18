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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.288.3");
  script_cve_id("CVE-2006-2313", "CVE-2006-2314", "CVE-2006-2753");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-288-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(5\.04|5\.10|6\.06\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-288-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-288-3");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/techdocs.50");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot, exim4, postfix' package(s) announced via the USN-288-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-288-1 described a PostgreSQL client vulnerability in the way
the >>'<< character is escaped in SQL queries. It was determined that
the PostgreSQL backends of Exim, Dovecot, and Postfix used this unsafe
escaping method.

For reference, these are the details of the original USN:

 CVE-2006-2313:
 Akio Ishida and Yasuo Ohgaki discovered a weakness in the handling of
 invalidly-encoded multibyte text data. If a client application
 processed untrusted input without respecting its encoding and applied
 standard string escaping techniques (such as replacing a single quote
 >>'<< with >>\'<< or >>''<<), the PostgreSQL server could interpret the
 resulting string in a way that allowed an attacker to inject arbitrary
 SQL commands into the resulting SQL query. The PostgreSQL server has
 been modified to reject such invalidly encoded strings now, which
 completely fixes the problem for some 'safe' multibyte encodings like
 UTF-8.

 CVE-2006-2314:
 However, there are some less popular and client-only multibyte
 encodings (such as SJIS, BIG5, GBK, GB18030, and UHC) which contain
 valid multibyte characters that end with the byte 0x5c, which is the
 representation of the backslash character >>\<< in ASCII. Many client
 libraries and applications use the non-standard, but popular way of
 escaping the >>'<< character by replacing all occurrences of it with
 >>\'<<. If a client application uses one of the affected encodings and
 does not interpret multibyte characters, and an attacker supplies a
 specially crafted byte sequence as an input string parameter, this
 escaping method would then produce a validly-encoded character and
 an excess >>'<< character which would end the string. All subsequent
 characters would then be interpreted as SQL code, so the attacker
 could execute arbitrary SQL commands.

 To fix this vulnerability end-to-end, client-side applications must
 be fixed to properly interpret multibyte encodings and use >>''<<
 instead of >>\'<<. However, as a precautionary measure, the sequence
 >>\'<< is now regarded as invalid when one of the affected client
 encodings is in use. If you depend on the previous behaviour, you
 can restore it by setting 'backslash_quote = on' in postgresql.conf.
 However, please be aware that this could render you vulnerable
 again.

 This issue does not affect you if you only use single-byte (like
 SQL_ASCII or the ISO-8859-X family) or unaffected multibyte (like
 UTF-8) encodings.

 Please see [link moved to references] for further
 details.");

  script_tag(name:"affected", value:"'dovecot, exim4, postfix' package(s) on Ubuntu 5.04, Ubuntu 5.10, Ubuntu 6.06.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU5.04") {

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-common", ver:"0.99.13-3ubuntu0.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-heavy", ver:"4.34-10ubuntu0.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postfix-pgsql", ver:"2.1.5-9ubuntu3.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU5.10") {

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-common", ver:"0.99.14-1ubuntu1.1", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-heavy", ver:"4.52-1ubuntu0.1", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postfix-pgsql", ver:"2.2.4-1ubuntu2.1", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"dovecot-common", ver:"1.0.beta3-3ubuntu5.1", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-heavy", ver:"4.60-3ubuntu3.1", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postfix-pgsql", ver:"2.2.10-1ubuntu0.1", rls:"UBUNTU6.06 LTS"))) {
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
