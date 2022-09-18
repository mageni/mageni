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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2288");
  script_cve_id("CVE-2020-14039", "CVE-2022-1962", "CVE-2022-28131", "CVE-2022-30629", "CVE-2022-30631", "CVE-2022-30632", "CVE-2022-30633", "CVE-2022-30634", "CVE-2022-30635", "CVE-2022-32148");
  script_tag(name:"creation_date", value:"2022-09-14 04:42:02 +0000 (Wed, 14 Sep 2022)");
  script_version("2022-09-15T10:11:06+0000");
  script_tag(name:"last_modification", value:"2022-09-15 10:11:06 +0000 (Thu, 15 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-15 15:18:00 +0000 (Mon, 15 Aug 2022)");

  script_name("Huawei EulerOS: Security Advisory for golang (EulerOS-SA-2022-2288)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2288");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2288");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'golang' package(s) announced via the EulerOS-SA-2022-2288 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Infinite loop in Read in crypto/rand before Go 1.17.11 and Go 1.18.3 on Windows allows attacker to cause an indefinite hang by passing a buffer larger than 1 << 32 - 1 bytes.(CVE-2022-30634)

Non-random values for ticket_age_add in session tickets in crypto/tls before Go 1.17.11 and Go 1.18.3 allow an attacker that can observe TLS handshakes to correlate successive connections by comparing ticket ages during session resumption.(CVE-2022-30629)

A flaw was found in golang. Calling the Reader.Read method on an archive that contains a large number of concatenated 0-length compressed files can cause a panic issue due to stack exhaustion.(CVE-2022-30631)

In Decoder.Skip in encoding/xml in Go before 1.17.12 and 1.18.x before 1.18.4, stack exhaustion and a panic can occur via a deeply nested XML document.(CVE-2022-28131)

A flaw was found in golang. Calling Glob on a path that contains a large number of path separators can cause a panic issue due to stack exhaustion. This can cause an attacker to impact availability.(CVE-2022-30632)

Uncontrolled recursion in Decoder.Decode in encoding/gob before Go 1.17.12 and Go 1.18.4 allows an attacker to cause a panic due to stack exhaustion via a message which contains deeply nested structures.(CVE-2022-30635)

Uncontrolled recursion in Unmarshal in encoding/xml before Go 1.17.12 and Go 1.18.4 allows an attacker to cause a panic due to stack exhaustion via unmarshalling an XML document into a Go struct which has a nested field that uses the 'any' field tag.(CVE-2022-30633)

Uncontrolled recursion in the Parse functions in go/parser before Go 1.17.12 and Go 1.18.4 allow an attacker to cause a panic due to stack exhaustion via deeply nested types or declarations.(CVE-2022-1962)

Improper exposure of client IP addresses in net/http before Go 1.17.12 and Go 1.18.4 can be triggered by calling httputil.ReverseProxy.ServeHTTP with a Request.Header map containing a nil value for the X-Forwarded-For header, which causes ReverseProxy to set the client IP as the value of the X-Forwarded-For header.(CVE-2022-32148)

In Go before 1.13.13 and 1.14.x before 1.14.5, Certificate.Verify may lack a check on the VerifyOptions.KeyUsages EKU requirements (if VerifyOptions.Roots equals nil and the installation is on Windows). Thus, X.509 certificate verification is incomplete.(CVE-2020-14039)");

  script_tag(name:"affected", value:"'golang' package(s) on Huawei EulerOS V2.0SP9(x86_64).");

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

if(release == "EULEROS-2.0SP9-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.13.3~10.h26.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-devel", rpm:"golang-devel~1.13.3~10.h26.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-help", rpm:"golang-help~1.13.3~10.h26.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
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
