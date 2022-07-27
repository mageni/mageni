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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1151");
  script_version("2020-01-23T10:53:37+0000");
  script_cve_id("CVE-2017-10053", "CVE-2017-10067", "CVE-2017-10074", "CVE-2017-10078", "CVE-2017-10081", "CVE-2017-10087", "CVE-2017-10089", "CVE-2017-10090", "CVE-2017-10096", "CVE-2017-10101", "CVE-2017-10102", "CVE-2017-10107", "CVE-2017-10108", "CVE-2017-10109", "CVE-2017-10110", "CVE-2017-10111", "CVE-2017-10115", "CVE-2017-10116", "CVE-2017-10135", "CVE-2017-10193", "CVE-2017-10198", "CVE-2017-10243");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 10:53:37 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 10:53:37 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for java-1.8.0-openjdk (EulerOS-SA-2017-1151)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP2");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1151");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'java-1.8.0-openjdk' package(s) announced via the EulerOS-SA-2017-1151 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the DCG implementation in the RMI component of OpenJDK failed to correctly handle references. A remote attacker could possibly use this flaw to execute arbitrary code with the privileges of RMI registry or a Java RMI application. (CVE-2017-10102)

Multiple flaws were discovered in the RMI, JAXP, ImageIO, Libraries, AWT, Hotspot, and Security components in OpenJDK. An untrusted Java application or applet could use these flaws to completely bypass Java sandbox restrictions. (CVE-2017-10107, CVE-2017-10096, CVE-2017-10101, CVE-2017-10089, CVE-2017-10090, CVE-2017-10087, CVE-2017-10111, CVE-2017-10110, CVE-2017-10074, CVE-2017-10067)

It was discovered that the LDAPCertStore class in the Security component of OpenJDK followed LDAP referrals to arbitrary URLs. A specially crafted LDAP referral URL could cause LDAPCertStore to communicate with non-LDAP servers. (CVE-2017-10116)

It was discovered that the Nashorn JavaScript engine in the Scripting component of OpenJDK could allow scripts to access Java APIs even when access to Java APIs was disabled. An untrusted JavaScript executed by Nashorn could use this flaw to bypass intended restrictions. (CVE-2017-10078)

It was discovered that the Security component of OpenJDK could fail to properly enforce restrictions defined for processing of X.509 certificate chains. A remote attacker could possibly use this flaw to make Java accept certificate using one of the disabled algorithms. (CVE-2017-10198)

A covert timing channel flaw was found in the DSA implementation in the JCE component of OpenJDK. A remote attacker able to make a Java application generate DSA signatures on demand could possibly use this flaw to extract certain information about the used key via a timing side channel. (CVE-2017-10115)

A covert timing channel flaw was found in the PKCS#8 implementation in the JCE component of OpenJDK. A remote attacker able to make a Java application repeatedly compare PKCS#8 key against an attacker controlled value could possibly use this flaw to determine the key via a timing side channel. (CVE-2017-10135)

It was discovered that the BasicAttribute and CodeSource classes in OpenJDK did not limit the amount of memory allocated when creating object instances from a serialized form. A specially crafted serialized input stream could cause Java to consume an excessive amount of memory. (CVE-2017-10108, CVE-2017-10109)

Multiple flaws were found in the Hotspot and Security components in OpenJDK. An untrusted Java application or applet could use these flaws to bypass certain Java sandbox restrictions. (CVE-2017-10081, CVE-2 ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'java-1.8.0-openjdk' package(s) on Huawei EulerOS V2.0SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"java", rpm:"java~1.8.0~openjdk~1.8.0.141~1.b16", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java", rpm:"java~1.8.0~openjdk~devel~1.8.0.141~1.b16", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java", rpm:"java~1.8.0~openjdk~headless~1.8.0.141~1.b16", rls:"EULEROS-2.0SP2"))) {
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