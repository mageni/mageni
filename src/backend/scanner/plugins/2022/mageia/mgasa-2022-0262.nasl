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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0262");
  script_cve_id("CVE-2022-1705", "CVE-2022-1962", "CVE-2022-28131", "CVE-2022-30630", "CVE-2022-30631", "CVE-2022-30632", "CVE-2022-30633", "CVE-2022-30635", "CVE-2022-32148");
  script_tag(name:"creation_date", value:"2022-07-18 04:46:52 +0000 (Mon, 18 Jul 2022)");
  script_version("2022-07-18T04:46:52+0000");
  script_tag(name:"last_modification", value:"2022-07-18 04:46:52 +0000 (Mon, 18 Jul 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2022-0262)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0262");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0262.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30639");
  script_xref(name:"URL", value:"https://groups.google.com/g/golang-announce/c/nqrv9fbR0zE");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/CUFBL2GZMN756YELNBCPJO3MTCGYXSYH/");
  script_xref(name:"URL", value:"https://go.dev/issue/53188");
  script_xref(name:"URL", value:"https://go.dev/issue/53423");
  script_xref(name:"URL", value:"https://go.dev/issue/53168");
  script_xref(name:"URL", value:"https://go.dev/issue/53611");
  script_xref(name:"URL", value:"https://go.dev/issue/53614");
  script_xref(name:"URL", value:"https://go.dev/issue/53416");
  script_xref(name:"URL", value:"https://go.dev/issue/53415");
  script_xref(name:"URL", value:"https://go.dev/issue/53616");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang' package(s) announced via the MGASA-2022-0262 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"net/http: improper sanitization of Transfer-Encoding header
The HTTP/1 client accepted some invalid Transfer-Encoding headers as
indicating a 'chunked' encoding. This could potentially allow for request
smuggling, but only if combined with an intermediate server that also
improperly failed to reject the header as invalid. (CVE-2022-1705)

When httputil.ReverseProxy.ServeHTTP was called with a Request.Header map
containing a nil value for the X-Forwarded-For header, ReverseProxy would
set the client IP as the value of the X-Forwarded-For header, contrary to
its documentation. In the more usual case where a Director function set
the X-Forwarded-For header value to nil, ReverseProxy would leave the
header unmodified as expected. (CVE-2022-32148)

compress/gzip: stack exhaustion in Reader.Read
Calling Reader.Read on an archive containing a large number of
concatenated 0-length compressed files can cause a panic due to stack
exhaustion. (CVE-2022-30631)

encoding/xml: stack exhaustion in Unmarshal
Calling Unmarshal on a XML document into a Go struct which has a nested
field that uses the any field tag can cause a panic due to stack
exhaustion. (CVE-2022-30633)

encoding/xml: stack exhaustion in Decoder.Skip
Calling Decoder.Skip when parsing a deeply nested XML document can cause a
panic due to stack exhaustion. (CVE-2022-28131)

encoding/gob: stack exhaustion in Decoder.Decode
Calling Decoder.Decode on a message which contains deeply nested
structures can cause a panic due to stack exhaustion. (CVE-2022-30635)

path/filepath: stack exhaustion in Glob
Calling Glob on a path which contains a large number of path separators
can cause a panic due to stack exhaustion. (CVE-2022-30632)

io/fs: stack exhaustion in Glob
Calling Glob on a path which contains a large number of path separators
can cause a panic due to stack exhaustion. (CVE-2022-30630)

go/parser: stack exhaustion in all Parse* functions
Calling any of the Parse functions on Go source code which contains deeply
nested types or declarations can cause a panic due to stack exhaustion.
(CVE-2022-1962)");

  script_tag(name:"affected", value:"'golang' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.17.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-bin", rpm:"golang-bin~1.17.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-docs", rpm:"golang-docs~1.17.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-misc", rpm:"golang-misc~1.17.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-race", rpm:"golang-race~1.17.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-shared", rpm:"golang-shared~1.17.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-src", rpm:"golang-src~1.17.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-tests", rpm:"golang-tests~1.17.12~1.mga8", rls:"MAGEIA8"))) {
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
