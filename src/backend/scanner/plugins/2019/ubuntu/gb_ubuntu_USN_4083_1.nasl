# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.844118");
  script_version("2019-08-08T09:10:13+0000");
  script_cve_id("CVE-2019-2762", "CVE-2019-2769", "CVE-2019-2786", "CVE-2019-2816",
                "CVE-2019-2818", "CVE-2019-2821", "CVE-2019-7317");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-08-08 09:10:13 +0000 (Thu, 08 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-01 02:01:18 +0000 (Thu, 01 Aug 2019)");
  script_name("Ubuntu Update for openjdk-lts USN-4083-1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.04 LTS|UBUNTU19\.04)");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-4083-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-lts'
  package(s) announced via the USN-4083-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenJDK did not sufficiently validate serial streams
before deserializing suppressed exceptions in some situations. An attacker
could use this to specially craft an object that, when deserialized, would
cause a denial of service. (CVE-2019-2762)

It was discovered that in some situations OpenJDK did not properly bound
the amount of memory allocated during object deserialization. An attacker
could use this to specially craft an object that, when deserialized, would
cause a denial of service (excessive memory consumption). (CVE-2019-2769)

It was discovered that OpenJDK did not properly restrict privileges in
certain situations. An attacker could use this to specially construct an
untrusted Java application or applet that could escape sandbox
restrictions. (CVE-2019-2786)

Jonathan Birch discovered that the Networking component of OpenJDK did not
properly validate URLs in some situations. An attacker could use this to
bypass restrictions on characters in URLs. (CVE-2019-2816)

It was discovered that the ChaCha20Cipher implementation in OpenJDK did not
use constant time computations in some situations. An attacker could use
this to expose sensitive information. (CVE-2019-2818)

It was discovered that the Java Secure Socket Extension (JSSE) component in
OpenJDK did not properly handle OCSP stapling messages during TLS handshake
in some situations. An attacker could use this to expose sensitive
information. (CVE-2019-2821)

It was discovered that OpenJDK incorrectly handled certain memory
operations. If a user or automated system were tricked into opening a
specially crafted PNG file, a remote attacker could use this issue to
cause OpenJDK to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2019-7317)");

  script_tag(name:"affected", value:"'openjdk-lts' package(s) on Ubuntu 19.04, Ubuntu 18.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"11.0.4+11-1ubuntu2~18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk-headless", ver:"11.0.4+11-1ubuntu2~18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.4+11-1ubuntu2~18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.4+11-1ubuntu2~18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-zero", ver:"11.0.4+11-1ubuntu2~18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.04") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"11.0.4+11-1ubuntu2~19.04", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk-headless", ver:"11.0.4+11-1ubuntu2~19.04", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.4+11-1ubuntu2~19.04", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.4+11-1ubuntu2~19.04", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-zero", ver:"11.0.4+11-1ubuntu2~19.04", rls:"UBUNTU19.04"))) {
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
