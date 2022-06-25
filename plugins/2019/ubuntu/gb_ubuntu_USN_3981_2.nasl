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
  script_oid("1.3.6.1.4.1.25623.1.0.844012");
  script_version("2019-05-17T10:04:07+0000");
  script_cve_id("CVE-2018-12130", "CVE-2018-12127", "CVE-2018-12126", "CVE-2018-16884",
                "CVE-2019-11091", "CVE-2019-3874", "CVE-2019-3882", "CVE-2019-9500",
                "CVE-2019-9503");
  script_tag(name:"cvss_base", value:"6.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:04:07 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-16 02:01:13 +0000 (Thu, 16 May 2019)");
  script_name("Ubuntu Update for linux-azure USN-3981-2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04 LTS");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3981-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure'
  package(s) announced via the USN-3981-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3981-1 fixed vulnerabilities in the Linux kernel for Ubuntu 18.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 18.04 LTS for Ubuntu
16.04 LTS and for the Linux Azure kernel for Ubuntu 14.04 LTS.

Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Giorgi Maisuradze, Dan
Horea Lutas, Andrei Lutas, Volodymyr Pikhur, Stephan van Schaik, Alyssa
Milburn, Sebastian sterlund, Pietro Frigo, Kaveh Razavi, Herbert Bos,
Cristiano Giuffrida, Moritz Lipp, Michael Schwarz, and Daniel Gruss
discovered that memory previously stored in microarchitectural fill buffers
of an Intel CPU core may be exposed to a malicious process that is
executing on the same CPU core. A local attacker could use this to expose
sensitive information. (CVE-2018-12130)

Brandon Falk, Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Stephan
van Schaik, Alyssa Milburn, Sebastian sterlund, Pietro Frigo, Kaveh
Razavi, Herbert Bos, and Cristiano Giuffrida discovered that memory
previously stored in microarchitectural load ports of an Intel CPU core may
be exposed to a malicious process that is executing on the same CPU core. A
local attacker could use this to expose sensitive information.
(CVE-2018-12127)

Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Marina Minkin, Daniel
Moghimi, Moritz Lipp, Michael Schwarz, Jo Van Bulck, Daniel Genkin, Daniel
Gruss, Berk Sunar, Frank Piessens, and Yuval Yarom discovered that memory
previously stored in microarchitectural store buffers of an Intel CPU core
may be exposed to a malicious process that is executing on the same CPU
core. A local attacker could use this to expose sensitive information.
(CVE-2018-12126)

Vasily Averin and Evgenii Shatokhin discovered that a use-after-free
vulnerability existed in the NFS41+ subsystem when multiple network
namespaces are in use. A local attacker in a container could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-16884)

Ke Sun, Henrique Kawakami, Kekai Hu, Rodrigo Branco, Volodrmyr Pikhur,
Moritz Lipp, Michael Schwarz, Daniel Gruss, Stephan van Schaik, Alyssa
Milburn, Sebastian sterlund, Pietro Frigo, Kaveh Razavi, Herbert Bos, and
Cristiano Giuffrida discovered that uncacheable memory previously stored in
microarchitectural buffers of an Intel CPU core may be exposed to a
malicious process that is executing on the same CPU core. A local attacker
could use this to expose sensitive information. (CVE-2019-11091)

Matteo Croce, Natale Vinto, and Andrea Spagnolo discovered that the cgroups
subsystem of the Linux kernel ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux-azure' package(s) on Ubuntu 16.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1013-oracle", ver:"4.15.0-1013.15~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1032-gcp", ver:"4.15.0-1032.34~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1045-azure", ver:"4.15.0-1045.49", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-50-generic", ver:"4.15.0-50.54~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-50-generic-lpae", ver:"4.15.0-50.54~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-50-lowlatency", ver:"4.15.0-50.54~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1045.49", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.15.0.1032.46", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-16.04", ver:"4.15.0.50.71", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-16.04", ver:"4.15.0.50.71", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.15.0.1032.46", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-16.04", ver:"4.15.0.50.71", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem", ver:"4.15.0.50.71", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"4.15.0.1013.7", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-16.04", ver:"4.15.0.50.71", rls:"UBUNTU16.04 LTS"))) {
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
