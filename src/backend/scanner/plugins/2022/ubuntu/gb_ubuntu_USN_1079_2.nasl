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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2011.1079.2");
  script_cve_id("CVE-2010-4448", "CVE-2010-4450", "CVE-2010-4465", "CVE-2010-4469", "CVE-2010-4470", "CVE-2010-4471", "CVE-2010-4472", "CVE-2010-4476", "CVE-2011-0706");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1079-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1079-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1079-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-6b18' package(s) announced via the USN-1079-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1079-1 fixed vulnerabilities in OpenJDK 6 for non-armel (ARM)
architectures. This update provides the corresponding updates for
OpenJDK 6 for use with the armel (ARM) architectures.

In order to build the armel (ARM) OpenJDK 6 update for Ubuntu 10.04
LTS, it was necessary to rebuild binutils and gcj-4.4 from Ubuntu
10.04 LTS updates.

Original advisory details:

 It was discovered that untrusted Java applets could create domain
 name resolution cache entries, allowing an attacker to manipulate
 name resolution within the JVM. (CVE-2010-4448)

 It was discovered that the Java launcher did not did not properly
 setup the LD_LIBRARY_PATH environment variable. A local attacker
 could exploit this to execute arbitrary code as the user invoking
 the program. (CVE-2010-4450)

 It was discovered that within the Swing library, forged timer events
 could allow bypass of SecurityManager checks. This could allow an
 attacker to access restricted resources. (CVE-2010-4465)

 It was discovered that certain bytecode combinations confused memory
 management within the HotSpot JVM. This could allow an attacker to
 cause a denial of service through an application crash or possibly
 inject code. (CVE-2010-4469)

 It was discovered that the way JAXP components were handled
 allowed them to be manipulated by untrusted applets. An attacker
 could use this to bypass XML processing restrictions and elevate
 privileges. (CVE-2010-4470)

 It was discovered that the Java2D subcomponent, when processing broken
 CFF fonts could leak system properties. (CVE-2010-4471)

 It was discovered that a flaw in the XML Digital Signature
 component could allow an attacker to cause untrusted code to
 replace the XML Digital Signature Transform or C14N algorithm
 implementations. (CVE-2010-4472)

 Konstantin Preisser and others discovered that specific double literals
 were improperly handled, allowing a remote attacker to cause a denial
 of service. (CVE-2010-4476)

 It was discovered that the JNLPClassLoader class when handling multiple
 signatures allowed remote attackers to gain privileges due to the
 assignment of an inappropriate security descriptor. (CVE-2011-0706)");

  script_tag(name:"affected", value:"'openjdk-6b18' package(s) on Ubuntu 9.10, Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b18-1.8.7-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b18-1.8.7-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b18-1.8.7-0ubuntu1~10.04.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b18-1.8.7-0ubuntu1~9.10.1", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b18-1.8.7-0ubuntu1~9.10.1", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b18-1.8.7-0ubuntu1~9.10.1", rls:"UBUNTU9.10"))) {
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
