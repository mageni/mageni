# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.845174");
  script_version("2021-12-24T05:24:58+0000");
  script_cve_id("CVE-2021-2341", "CVE-2021-2369", "CVE-2021-2388", "CVE-2021-35550", "CVE-2021-35556", "CVE-2021-35559", "CVE-2021-35561", "CVE-2021-35564", "CVE-2021-35565", "CVE-2021-35567", "CVE-2021-35578", "CVE-2021-35586", "CVE-2021-35588", "CVE-2021-35603");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-12-24 11:10:42 +0000 (Fri, 24 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-18 02:00:32 +0000 (Sat, 18 Dec 2021)");
  script_name("Ubuntu: Security Advisory for openjdk-8 (USN-5202-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.04 LTS|UBUNTU20\.04 LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5202-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-December/006320.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-8'
  package(s) announced via the USN-5202-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Varnavas Papaioannou discovered that the FTP client implementation in
OpenJDK accepted alternate server IP addresses when connecting with FTP
passive mode. An attacker controlling an FTP server that an application
connects to could possibly use this to expose sensitive information
(rudimentary port scans). This issue only affected Ubuntu 16.04 ESM,
Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 21.04. (CVE-2021-2341)

Markus Loewe discovered that OpenJDK did not properly handle JAR files
containing multiple manifest files. An attacker could possibly use
this to bypass JAR signature verification. This issue only affected
Ubuntu 16.04 ESM, Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu
21.04. (CVE-2021-2369)

Huixin Ma discovered that the Hotspot VM in OpenJDK did not properly
perform range check elimination in some situations. An attacker could
possibly use this to construct a Java class that could bypass Java
sandbox restrictions. This issue only affected Ubuntu 16.04 ESM,
Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 21.04. (CVE-2021-2388)

Asaf Greenholts discovered that OpenJDK preferred certain weak ciphers by
default. An attacker could possibly use this to expose sensitive
information. (CVE-2021-35550)

It was discovered that the Rich Text Format (RTF) Parser in OpenJDK did not
properly restrict the amount of memory allocated in some situations. An
attacker could use this to specially craft an RTF file that caused a denial
of service. (CVE-2021-35556)

It was discovered that the Rich Text Format (RTF) Reader in OpenJDK did not
properly restrict the amount of memory allocated in some situations. An
attacker could use this to specially craft an RTF file that caused a denial
of service. (CVE-2021-35559)

Markus Loewe discovered that the HashMap and HashSet implementations in
OpenJDK did not properly validate load factors during deserialization. An
attacker could use this to cause a denial of service (excessive memory
consumption). (CVE-2021-35561)

It was discovered that the Keytool component in OpenJDK did not properly
handle certificates with validity ending dates in the far future. An
attacker could use this to specially craft a certificate that when imported
could corrupt a keystore. (CVE-2021-35564)

Tristen Hayfield discovered that the HTTP server implementation in OpenJDK
did not properly handle TLS session close in some situations. A remote
attacker could possibly use this to cause a denial of service (application
infinite loop). (CVE-2021-35565)

Chuck Hunley discovered that the Kerberos implementation in OpenJDK did not
correctly report subject principals  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'openjdk-8' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.13+8-0ubuntu1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.13+8-0ubuntu1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-zero", ver:"11.0.13+8-0ubuntu1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u312-b07-0ubuntu1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u312-b07-0ubuntu1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-zero", ver:"8u312-b07-0ubuntu1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.13+8-0ubuntu1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.13+8-0ubuntu1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-zero", ver:"11.0.13+8-0ubuntu1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u312-b07-0ubuntu1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u312-b07-0ubuntu1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-zero", ver:"8u312-b07-0ubuntu1~20.04", rls:"UBUNTU20.04 LTS"))) {
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