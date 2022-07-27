# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2018.1206");
  script_version("2020-01-23T11:17:27+0000");
  script_cve_id("CVE-2018-6914", "CVE-2018-8777", "CVE-2018-8778", "CVE-2018-8779", "CVE-2018-8780");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 11:17:27 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:17:27 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for ruby (EulerOS-SA-2018-1206)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP2");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1206");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'ruby' package(s) announced via the EulerOS-SA-2018-1206 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that the tmpdir and tempfile modules did not sanitize their file name argument. An attacker with control over the name could create temporary files and directories outside of the dedicated directory.(CVE-2018-6914)

A integer underflow was found in the way String#unpack decodes the unpacking format. An attacker, able to control the unpack format, could use this flaw to disclose arbitrary parts of the application's memory.(CVE-2018-8778)

It was found that the UNIXSocket::open and UNIXServer::open ruby methods did not handle the NULL byte properly. An attacker, able to inject NULL bytes in the socket path, could possibly trigger an unspecified behavior of the ruby script.(CVE-2018-8779)

It was found that the methods from the Dir class did not properly handle strings containing the NULL byte. An attacker, able to inject NULL bytes in a path, could possibly trigger an unspecified behavior of the ruby script.(CVE-2018-8780)

It was found that WEBrick could be forced to use an excessive amount of memory during the processing of HTTP requests, leading to a Denial of Service. An attacker could use this flaw to send huge requests to a WEBrick application, resulting in the server running out of memory.(CVE-2018-8777)");

  script_tag(name:"affected", value:"'ruby' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~2.0.0.648~33.h11", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~2.0.0.648~33.h11", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~2.0.0.648~33.h11", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);