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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0579");
  script_cve_id("CVE-2020-36327", "CVE-2021-28965", "CVE-2021-31799", "CVE-2021-31810", "CVE-2021-32066", "CVE-2021-41816", "CVE-2021-41817", "CVE-2021-41819");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-31T07:41:30+0000");
  script_tag(name:"last_modification", value:"2022-01-31 07:41:30 +0000 (Mon, 31 Jan 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-17 19:03:00 +0000 (Mon, 17 May 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0579)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0579");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0579.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29004");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4922-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/VF3QUOV6OJPCL64ZDHTQRENRJQZPZO6S/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CMW3G6JZK6A7ZRJZ7VOMELHWOQBYPIOY/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5020-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/MWXHK5UUHVSHF7HTHMX6JY3WXDVNIHSL/");
  script_xref(name:"URL", value:"http://www.ruby-lang.org/en/news/2021/11/15/date-parsing-method-regexp-dos-cve-2021-41817/");
  script_xref(name:"URL", value:"http://www.ruby-lang.org/en/news/2021/11/24/buffer-overrun-in-cgi-escape_html-cve-2021-41816/");
  script_xref(name:"URL", value:"http://www.ruby-lang.org/en/news/2021/11/24/cookie-prefix-spoofing-in-cgi-cookie-parse-cve-2021-41819/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby' package(s) announced via the MGASA-2021-0579 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Bundler sometimes chooses a dependency source based on the highest gem
version number, which means that a rogue gem found at a public source
may be chosen, even if the intended choice was a private gem that is a
dependency of another private gem that is explicitly depended on by the
application. (CVE-2020-36327)

The REXML gem does not properly address XML round-trip issues. An
incorrect document can be produced after parsing and serializing.
(CVE-2021-28965)

In RDoc it is possible to execute arbitrary code via <pipe> and tags in a
filename. (CVE-2021-31799)

A malicious FTP server can use the PASV response to trick Net::FTP into
connecting back to a given IP address and port. This potentially makes
curl extract information about services that are otherwise private and not
disclosed (e.g., the attacker can conduct port scans and service banner
extractions). (CVE-2021-31810)

Ruby Net::IMAP does not raise an exception when StartTLS fails with an
unknown response, which might allow man-in-the-middle attackers to bypass
the TLS protections by leveraging a network position between the client
and the registry to block the StartTLS command, aka a 'StartTLS stripping
attack.' (CVE-2021-32066)

Buffer Overrun in CGI.escape_html (CVE-2021-41816)

Regular Expression Denial of Service Vulnerability of Date Parsing Methods
(CVE-2021-41817)

Cookie Prefix Spoofing in CGI::Cookie.parse (CVE-2021-41819)");

  script_tag(name:"affected", value:"'ruby' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ruby2.7", rpm:"lib64ruby2.7~2.7.5~33.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby2.7", rpm:"libruby2.7~2.7.5~33.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~2.7.5~33.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-RubyGems", rpm:"ruby-RubyGems~3.1.2~33.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-bigdecimal", rpm:"ruby-bigdecimal~2.0.0~33.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-bundler", rpm:"ruby-bundler~2.2.24~33.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~2.7.5~33.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-did_you_mean", rpm:"ruby-did_you_mean~1.4.0~33.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-doc", rpm:"ruby-doc~2.7.5~33.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-io-console", rpm:"ruby-io-console~0.5.6~33.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~2.7.5~33.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-json", rpm:"ruby-json~2.3.0~33.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-net-telnet", rpm:"ruby-net-telnet~0.2.0~33.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-openssl", rpm:"ruby-openssl~2.1.3~33.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-power_assert", rpm:"ruby-power_assert~1.1.7~33.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-psych", rpm:"ruby-psych~3.1.0~33.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rake", rpm:"ruby-rake~13.0.1~33.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rdoc", rpm:"ruby-rdoc~6.2.1.1~33.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-test-unit", rpm:"ruby-test-unit~3.3.4~33.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-xmlrpc", rpm:"ruby-xmlrpc~0.3.0~33.2.mga8", rls:"MAGEIA8"))) {
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
