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
  script_oid("1.3.6.1.4.1.25623.1.0.845299");
  script_version("2022-05-19T12:23:28+0000");
  script_cve_id("CVE-2022-21248", "CVE-2022-21277", "CVE-2022-21282", "CVE-2022-21283", "CVE-2022-21291", "CVE-2022-21293", "CVE-2022-21294", "CVE-2022-21296", "CVE-2022-21299", "CVE-2022-21305", "CVE-2022-21340", "CVE-2022-21341", "CVE-2022-21360", "CVE-2022-21366", "CVE-2022-21365");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-05-20 09:52:18 +0000 (Fri, 20 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-21 22:23:00 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-03-30 01:00:28 +0000 (Wed, 30 Mar 2022)");
  script_name("Ubuntu: Security Advisory for openjdk-lts (USN-5313-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU21\.10|UBUNTU18\.04 LTS|UBUNTU20\.04 LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5313-2");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2022-March/006476.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-lts'
  package(s) announced via the USN-5313-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5313-1 fixed vulnerabilities and added features in OpenJDK.
Unfortunately, that update introduced a regression in OpenJDK 11 that
could impact interoperability with some popular HTTP/2 servers making
it unable to connect to said servers. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

It was discovered that OpenJDK incorrectly handled deserialization filters.
An attacker could possibly use this issue to insert, delete or obtain
sensitive information. (CVE-2022-21248)

It was discovered that OpenJDK incorrectly read uncompressed TIFF files.
An attacker could possibly use this issue to cause a denial of service via
a specially crafted TIFF file. (CVE-2022-21277)

Jonni Passki discovered that OpenJDK incorrectly verified access
restrictions when performing URI resolution. An attacker could possibly
use this issue to obtain sensitive information. (CVE-2022-21282)

It was discovered that OpenJDK incorrectly handled certain regular
expressions in the Pattern class implementation. An attacker could
possibly use this issue to cause a denial of service. (CVE-2022-21283)

It was discovered that OpenJDK incorrectly handled specially crafted Java
class files. An attacker could possibly use this issue to cause a denial
of service. (CVE-2022-21291)

Markus Loewe discovered that OpenJDK incorrectly validated attributes
during object deserialization. An attacker could possibly use this issue
to cause a denial of service. (CVE-2022-21293, CVE-2022-21294)

Dan Rabe discovered that OpenJDK incorrectly verified access permissions
in the JAXP component. An attacker could possibly use this to specially
craft an XML file to obtain sensitive information. (CVE-2022-21296)

It was discovered that OpenJDK incorrectly handled XML entities. An
attacker could use this to specially craft an XML file that, when parsed,
would possibly cause a denial of service. (CVE-2022-21299)

Zhiqiang Zang discovered that OpenJDK incorrectly handled array indexes.
An attacker could possibly use this issue to obtain sensitive information.
(CVE-2022-21305)

It was discovered that OpenJDK incorrectly read very long attributes
values in JAR file manifests. An attacker could possibly use this to
specially craft JAR file to cause a denial of service. (CVE-2022-21340)

It was discovered that OpenJDK incorrectly validated input from serialized
streams. An attacker cold possibly use this issue to bypass sandbox
restrictions. (CVE-2022-21341)

Fabian Meumertzheim discovered that OpenJDK incorrectly handled certain
specially crafted BMP or TIFF files. An att ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'openjdk-lts' package(s) on Ubuntu 21.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS.");

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

if(release == "UBUNTU21.10") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"11.0.14.1+1-0ubuntu1~21.10", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk-headless", ver:"11.0.14.1+1-0ubuntu1~21.10", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.14.1+1-0ubuntu1~21.10", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.14.1+1-0ubuntu1~21.10", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-zero", ver:"11.0.14.1+1-0ubuntu1~21.10", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"11.0.14.1+1-0ubuntu1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk-headless", ver:"11.0.14.1+1-0ubuntu1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.14.1+1-0ubuntu1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.14.1+1-0ubuntu1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-zero", ver:"11.0.14.1+1-0ubuntu1~18.04", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"11.0.14.1+1-0ubuntu1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk-headless", ver:"11.0.14.1+1-0ubuntu1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.14.1+1-0ubuntu1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.14.1+1-0ubuntu1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-zero", ver:"11.0.14.1+1-0ubuntu1~20.04", rls:"UBUNTU20.04 LTS"))) {
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