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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2016.1080");
  script_version("2020-01-23T10:42:20+0000");
  script_cve_id("CVE-2016-5542", "CVE-2016-5554", "CVE-2016-5573", "CVE-2016-5582", "CVE-2016-5597");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 10:42:20 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 10:42:20 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for java-1.7.0-openjdk (EulerOS-SA-2016-1080)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP1");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1080");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'java-1.7.0-openjdk' package(s) announced via the EulerOS-SA-2016-1080 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Libraries component of OpenJDK did not restrict the set of algorithms used for JAR integrity verification. This flaw could allow an attacker to modify content of the JAR file that used weak signing key or hash algorithm.(CVE-2016-5542)

A flaw was found in the way the JMX component of OpenJDK handled classloaders. An untrusted Java application or applet could use this flaw to bypass certain Java sandbox restrictions.(CVE-2016-5554)

It was discovered that the Hotspot component of OpenJDK did not properly check received Java Debug Wire Protocol (JDWP) packets. An attacker could possibly use this flaw to send debugging commands to a Java program running with debugging enabled if they could make victim's browser send HTTP requests to the JDWP port of the debugged application.(CVE-2016-5573)

It was discovered that the Hotspot component of OpenJDK did not properly check arguments of the System.arraycopy() function in certain cases. An untrusted Java application or applet could use this flaw to corrupt virtual machine's memory and completely bypass Java sandbox restrictions.(CVE-2016-5582)

A flaw was found in the way the Networking component of OpenJDK handled HTTP proxy authentication. A Java application could possibly expose HTTPS server authentication credentials via a plain text network connection to an HTTP proxy if proxy asked for authentication.(CVE-2016-5597)");

  script_tag(name:"affected", value:"'java-1.7.0-openjdk' package(s) on Huawei EulerOS V2.0SP1.");

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

if(release == "EULEROS-2.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"java", rpm:"java~1.7.0~openjdk~1.7.0.121~2.6.8.0", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java", rpm:"java~1.7.0~openjdk~devel~1.7.0.121~2.6.8.0", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java", rpm:"java~1.7.0~openjdk~headless~1.7.0.121~2.6.8.0", rls:"EULEROS-2.0SP1"))) {
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