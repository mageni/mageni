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
  script_oid("1.3.6.1.4.1.25623.1.0.844116");
  script_version("2019-08-08T09:10:13+0000");
  script_cve_id("CVE-2019-2745", "CVE-2019-2762", "CVE-2019-2769", "CVE-2019-2786",
                "CVE-2019-2816", "CVE-2019-2842", "CVE-2019-7317");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-08-08 09:10:13 +0000 (Thu, 08 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-01 02:01:11 +0000 (Thu, 01 Aug 2019)");
  script_name("Ubuntu Update for openjdk-8 USN-4080-1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04 LTS");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-4080-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-8'
  package(s) announced via the USN-4080-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Keegan Ryan discovered that the ECC implementation in OpenJDK was not
sufficiently resilient to side-channel attacks. An attacker could possibly
use this to expose sensitive information. (CVE-2019-2745)

It was discovered that OpenJDK did not sufficiently validate serial streams
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

Nati Nimni discovered that the Java Cryptography Extension component in
OpenJDK did not properly perform array bounds checking in some situations.
An attacker could use this to cause a denial of service. (CVE-2019-2842)

It was discovered that OpenJDK incorrectly handled certain memory
operations. If a user or automated system were tricked into opening a
specially crafted PNG file, a remote attacker could use this issue to
cause OpenJDK to crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2019-7317)");

  script_tag(name:"affected", value:"'openjdk-8' package(s) on Ubuntu 16.04 LTS.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jdk", ver:"8u222-b10-1ubuntu1~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jdk-headless", ver:"8u222-b10-1ubuntu1~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u222-b10-1ubuntu1~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u222-b10-1ubuntu1~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-jamvm", ver:"8u222-b10-1ubuntu1~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-zero", ver:"8u222-b10-1ubuntu1~16.04.1", rls:"UBUNTU16.04 LTS"))) {
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
