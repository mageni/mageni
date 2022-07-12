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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0071");
  script_cve_id("CVE-2018-11212", "CVE-2019-2422", "CVE-2019-2426", "CVE-2019-2449", "CVE-2019-2540");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-07 20:15:00 +0000 (Thu, 07 Jan 2021)");

  script_name("Mageia: Security Advisory (MGASA-2019-0071)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0071");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0071.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24293");
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html#AppendixJAVA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.8.0-openjdk' package(s) announced via the MGASA-2019-0071 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vulnerability in the Java Advanced Management Console component of
Oracle Java SE (subcomponent: Server). The supported version that is
affected is Java Advanced Management Console: 2.12. Easily exploitable
vulnerability allows unauthenticated attacker with network access via
multiple protocols to compromise Java Advanced Management Console.
Successful attacks require human interaction from a person other than
the attacker and while the vulnerability is in Java Advanced Management
Console, attacks may significantly impact additional products.
Successful attacks of this vulnerability can result in unauthorized
update, insert or delete access to some of Java Advanced Management
Console accessible data as well as unauthorized read access to a subset
of Java Advanced Management Console accessible data. (CVE-2019-2540)

An issue was discovered in libjpeg 9a. The alloc_sarray function in
jmemmgr.c allows remote attackers to cause a denial of service
(divide-by-zero error) via a crafted file. (CVE-2018-11212)

Vulnerability in the Java SE component of Oracle Java SE (subcomponent:
Networking). Supported versions that are affected are Java SE: 7u201,
8u192 and 11.0.1, Java SE Embedded: 8u191. Difficult to exploit
vulnerability allows unauthenticated attacker with network access via
multiple protocols to compromise Java SE. Successful attacks of this
vulnerability can result in unauthorized read access to a subset of Java
SE accessible data. Note: This vulnerability applies to Java deployments,
typically in clients running sandboxed Java Web Start applications or
sandboxed Java applets (in Java SE 8), that load and run untrusted code
(e.g., code that comes from the internet) and rely on the Java sandbox
for security. This vulnerability can also be exploited by using APIs in
the specified Component, e.g., through a web service which supplies data
to the APIs. (CVE-2019-2426)

Vulnerability in the Java SE component of Oracle Java SE (subcomponent:
Deployment). The supported version that is affected is Java SE: 8u192.
Difficult to exploit vulnerability allows unauthenticated attacker with
network access via multiple protocols to compromise Java SE. Successful
attacks require human interaction from a person other than the attacker.
Successful attacks of this vulnerability can result in unauthorized
ability to cause a partial denial of service (partial DOS) of Java SE.
Note: This vulnerability applies to Java deployments, typically in
clients running sandboxed Java Web Start applications or sandboxed Java
applets (in Java SE 8), that load and run untrusted code (e.g., code
that comes from the internet) and rely on the Java sandbox for security.
This vulnerability does not apply to Java deployments, typically in
servers, that load and run only trusted code (e.g., code installed by
an administrator). (CVE-2019-2449)

Vulnerability in the Java SE component of Oracle Java SE ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'java-1.8.0-openjdk' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.201~1.b09.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-accessibility", rpm:"java-1.8.0-openjdk-accessibility~1.8.0.201~1.b09.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.201~1.b09.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.201~1.b09.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.201~1.b09.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.201~1.b09.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc-zip", rpm:"java-1.8.0-openjdk-javadoc-zip~1.8.0.201~1.b09.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-openjfx", rpm:"java-1.8.0-openjdk-openjfx~1.8.0.201~1.b09.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-openjfx-devel", rpm:"java-1.8.0-openjdk-openjfx-devel~1.8.0.201~1.b09.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.201~1.b09.2.mga6", rls:"MAGEIA6"))) {
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
