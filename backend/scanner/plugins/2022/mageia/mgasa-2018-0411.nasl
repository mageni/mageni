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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0411");
  script_cve_id("CVE-2017-17742", "CVE-2018-16395", "CVE-2018-16396", "CVE-2018-6914", "CVE-2018-8777", "CVE-2018-8778", "CVE-2018-8779", "CVE-2018-8780");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0411)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0411");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0411.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22844");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2018/03/28/http-response-splitting-in-webrick-cve-2017-17742/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2018/03/28/unintentional-file-and-directory-creation-with-directory-traversal-cve-2018-6914/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2018/03/28/large-request-dos-in-webrick-cve-2018-8777/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2018/03/28/buffer-under-read-unpack-cve-2018-8778/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2018/03/28/poisoned-nul-byte-unixsocket-cve-2018-8779/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2018/03/28/poisoned-nul-byte-dir-cve-2018-8780/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2018/10/17/openssl-x509-name-equality-check-does-not-work-correctly-cve-2018-16395/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2018/10/17/not-propagated-taint-flag-in-some-formats-of-pack-cve-2018-16396/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2018/03/28/ruby-2-2-10-released/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby' package(s) announced via the MGASA-2018-0411 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ruby before 2.2.10 allows an HTTP Response Splitting attack. An attacker
can inject a crafted key and value into an HTTP response for the HTTP
server of WEBrick (CVE-2017-17742).

Directory traversal vulnerability in the Dir.mktmpdir method in the tmpdir
library in Ruby before 2.2.10 might allow attackers to create arbitrary
directories or files via a .. (dot dot) in the prefix argument
(CVE-2018-6914).

In Ruby before 2.2.10, an attacker can pass a large HTTP request with a
crafted header to WEBrick server or a crafted body to WEBrick
server/handler and cause a denial of service (memory consumption)
(CVE-2018-8777).

In Ruby before 2.2.10, an attacker controlling the unpacking format
(similar to format string vulnerabilities) can trigger a buffer under-read
in the String#unpack method, resulting in a massive and controlled
information disclosure (CVE-2018-8778).

In Ruby before 2.2.10, the UNIXServer.open and UNIXSocket.open methods are
not checked for null characters. It may be connected to an unintended
socket (CVE-2018-8779).

In Ruby before 2.2.10, the Dir.open, Dir.new, Dir.entries and Dir.empty?
methods do not check NULL characters. When using the corresponding method,
unintentional directory traversal may be performed (CVE-2018-8780).

Due to a bug in the equality check of OpenSSL::X509::Name, if a malicious
X.509 certificate is passed to compare with an existing certificate, there
is a possibility to be judged incorrectly that they are equal
(CVE-2018-16395).

In Array#pack and String#unpack with some formats, the tainted flags of
the original data are not propagated to the returned string/array
(CVE-2018-16396).");

  script_tag(name:"affected", value:"'ruby' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ruby2.2", rpm:"lib64ruby2.2~2.2.10~16.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby2.2", rpm:"libruby2.2~2.2.10~16.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~2.2.10~16.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~2.2.10~16.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-doc", rpm:"ruby-doc~2.2.10~16.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-io-console", rpm:"ruby-io-console~0.4.3~16.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~2.2.10~16.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-power_assert", rpm:"ruby-power_assert~0.2.2~16.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-test-unit", rpm:"ruby-test-unit~3.0.8~16.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-tk", rpm:"ruby-tk~2.2.10~16.1.mga6", rls:"MAGEIA6"))) {
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
