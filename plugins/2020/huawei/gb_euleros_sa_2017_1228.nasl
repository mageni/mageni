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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1228");
  script_version("2020-01-23T11:00:01+0000");
  script_cve_id("CVE-2016-10207", "CVE-2017-5581", "CVE-2017-7392", "CVE-2017-7393", "CVE-2017-7394", "CVE-2017-7395", "CVE-2017-7396");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 11:00:01 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:00:01 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for tigervnc (EulerOS-SA-2017-1228)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP2");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1228");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'tigervnc' package(s) announced via the EulerOS-SA-2017-1228 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A denial of service flaw was found in the TigerVNC's Xvnc server. A remote unauthenticated attacker could use this flaw to make Xvnc crash by terminating the TLS handshake process early. (CVE-2016-10207)

A double free flaw was found in the way TigerVNC handled ClientFence messages. A remote, authenticated attacker could use this flaw to make Xvnc crash by sending specially crafted ClientFence messages, resulting in denial of service. (CVE-2017-7393)

A missing input sanitization flaw was found in the way TigerVNC handled credentials. A remote unauthenticated attacker could use this flaw to make Xvnc crash by sending specially crafted usernames, resulting in denial of service. (CVE-2017-7394)

An integer overflow flaw was found in the way TigerVNC handled ClientCutText messages. A remote, authenticated attacker could use this flaw to make Xvnc crash by sending specially crafted ClientCutText messages, resulting in denial of service. (CVE-2017-7395)

A buffer overflow flaw, leading to memory corruption, was found in TigerVNC viewer. A remote malicious VNC server could use this flaw to crash the client vncviewer process resulting in denial of service. (CVE-2017-5581)

A memory leak flaw was found in the way TigerVNC handled termination of VeNCrypt connections. A remote unauthenticated attacker could repeatedly send connection requests to the Xvnc server, causing it to consume large amounts of memory resources over time, and ultimately leading to a denial of service due to memory exhaustion. (CVE-2017-7392)

A memory leak flaw was found in the way TigerVNC handled client connections. A remote unauthenticated attacker could repeatedly send connection requests to the Xvnc server, causing it to consume large amounts of memory resources over time, and ultimately leading to a denial of service due to memory exhaustion. (CVE-2017-7396)");

  script_tag(name:"affected", value:"'tigervnc' package(s) on Huawei EulerOS V2.0SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"tigervnc", rpm:"tigervnc~1.8.0~1", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-icons", rpm:"tigervnc-icons~1.8.0~1", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-license", rpm:"tigervnc-license~1.8.0~1", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-server", rpm:"tigervnc-server~1.8.0~1", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-server-minimal", rpm:"tigervnc-server-minimal~1.8.0~1", rls:"EULEROS-2.0SP2"))) {
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