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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2018.3641.2");
  script_cve_id("CVE-2018-1000199", "CVE-2018-1087", "CVE-2018-8897");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3641-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3641-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3641-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-lts-trusty' package(s) announced via the USN-3641-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3641-1 fixed vulnerabilities in the Linux kernel for Ubuntu 14.04
LTS, Ubuntu 16.04 LTS, and Ubuntu 17.10. This update provides the
corresponding updates for Ubuntu 12.04 ESM.

Nick Peterson discovered that the Linux kernel did not properly handle
debug exceptions following a MOV/POP to SS instruction. A local attacker
could use this to cause a denial of service (system crash). This issue only
affected the amd64 architecture. (CVE-2018-8897)

Andy Lutomirski discovered that the KVM subsystem of the Linux kernel did
not properly emulate the ICEBP instruction following a MOV/POP to SS
instruction. A local attacker in a KVM virtual machine could use this to
cause a denial of service (guest VM crash) or possibly escalate privileges
inside of the virtual machine. This issue only affected the i386 and amd64
architectures. (CVE-2018-1087)

Andy Lutomirski discovered that the Linux kernel did not properly perform
error handling on virtualized debug registers. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2018-1000199)");

  script_tag(name:"affected", value:"'linux, linux-lts-trusty' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-147-generic-lpae", ver:"3.13.0-147.196~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-147-generic", ver:"3.13.0-147.196~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-134-generic-pae", ver:"3.2.0-134.180", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-134-generic", ver:"3.2.0-134.180", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-134-highbank", ver:"3.2.0-134.180", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-134-omap", ver:"3.2.0-134.180", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-134-powerpc-smp", ver:"3.2.0-134.180", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-134-powerpc64-smp", ver:"3.2.0-134.180", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-134-virtual", ver:"3.2.0-134.180", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-lts-trusty", ver:"3.13.0.147.138", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-trusty", ver:"3.13.0.147.138", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-pae", ver:"3.2.0.134.149", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"3.2.0.134.149", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-highbank", ver:"3.2.0.134.149", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-omap", ver:"3.2.0.134.149", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc-smp", ver:"3.2.0.134.149", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc", ver:"3.2.0.134.149", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64-smp", ver:"3.2.0.134.149", rls:"UBUNTU12.04 LTS"))) {
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
