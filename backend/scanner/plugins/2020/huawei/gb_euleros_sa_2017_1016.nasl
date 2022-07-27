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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1016");
  script_version("2020-01-23T15:42:05+0000");
  script_cve_id("CVE-2016-5546", "CVE-2016-5547", "CVE-2016-5548", "CVE-2016-5552", "CVE-2017-3231", "CVE-2017-3241", "CVE-2017-3252", "CVE-2017-3253", "CVE-2017-3261", "CVE-2017-3272", "CVE-2017-3289");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 15:42:05 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 10:43:55 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for java-1.8.0-openjdk (EulerOS-SA-2017-1016)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP2");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1016");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'java-1.8.0-openjdk' package(s) announced via the EulerOS-SA-2017-1016 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the RMI registry and DCG implementations in the RMI component of OpenJDK performed deserialization of untrusted inputs. A remote attacker could possibly use this flaw to execute arbitrary code with the privileges of RMI registry or a Java RMI application. (CVE-2017-3241)

Multiple flaws were discovered in the Libraries and Hotspot components in OpenJDK. An untrusted Java application or applet could use these flaws to completely bypass Java sandbox restrictions. (CVE-2017-3272, CVE-2017-3289)

A covert timing channel flaw was found in the DSA implementation in the Libraries component of OpenJDK. A remote attacker could possibly use this flaw to extract certain information about the used key via a timing side channel. (CVE-2016-5548)

It was discovered that the Libraries component of OpenJDK accepted ECSDA signatures using non-canonical DER encoding. This could cause a Java application to accept signature in an incorrect format not accepted by other cryptographic tools. (CVE-2016-5546)

It was discovered that the 2D component of OpenJDK performed parsing of iTXt and zTXt PNG image chunks even when configured to ignore metadata. An attacker able to make a Java application parse a specially crafted PNG image could cause the application to consume an excessive amount of memory. (CVE-2017-3253)

It was discovered that the Libraries component of OpenJDK did not validate the length of the object identifier read from the DER input before allocating memory to store the OID. An attacker able to make a Java application decode a specially crafted DER input could cause the application to consume an excessive amount of memory. (CVE-2016-5547)

It was discovered that the JAAS component of OpenJDK did not use the correct way to extract user DN from the result of the user search LDAP query. A specially crafted user LDAP entry could cause the application to use an incorrect DN. (CVE-2017-3252)

It was discovered that the Networking component of OpenJDK failed to properly parse user info from the URL. A remote attacker could cause a Java application to incorrectly parse an attacker supplied URL and interpret it differently from other applications processing the same URL. (CVE-2016-5552)

Multiple flaws were found in the Networking components in OpenJDK. An untrusted Java application or applet could use these flaws to bypass certain Java sandbox restrictions. (CVE-2017-3261, CVE-2017-3231)

A flaw was found in the way the DES/3DES cipher was used as part of the TLS/SSL protocol. A man-in-the-middle attacker could use this flaw to recover some plaintext data by capturing large amounts of encrypted traffic between TLS/SSL server and client if the communication used a DES/3DES based ciphersuite. (CVE-2016-2183)");

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

  if(!isnull(res = isrpmvuln(pkg:"java", rpm:"java~1.8.0~openjdk~1.8.0.121~0.b13", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java", rpm:"java~1.8.0~openjdk~devel~1.8.0.121~0.b13", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java", rpm:"java~1.8.0~openjdk~headless~1.8.0.121~0.b13", rls:"EULEROS-2.0SP2"))) {
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