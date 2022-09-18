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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.346.1");
  script_cve_id("CVE-2006-2934", "CVE-2006-2935", "CVE-2006-2936", "CVE-2006-3468", "CVE-2006-3745", "CVE-2006-4093", "CVE-2006-4145");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-346-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(5\.04|5\.10|6\.06\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-346-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-346-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-source-2.6.10, linux-source-2.6.12, linux-source-2.6.15' package(s) announced via the USN-346-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A Denial of service vulnerability was reported in iptables' SCTP
conntrack module. On computers which use this iptables module, a
remote attacker could exploit this to trigger a kernel crash.
(CVE-2006-2934)

A buffer overflow has been discovered in the dvd_read_bca() function.
By inserting a specially crafted DVD, USB stick, or similar
automatically mounted removable device, a local user could crash the
machine or potentially even execute arbitrary code with full root
privileges. (CVE-2006-2935)

The ftdi_sio driver for serial USB ports did not limit the amount of
pending data to be written. A local user could exploit this to drain
all available kernel memory and thus render the system unusable.
(CVE-2006-2936)

James McKenzie discovered a Denial of Service vulnerability in the NFS
driver. When exporting an ext3 file system over NFS, a remote attacker
could exploit this to trigger a file system panic by sending a
specially crafted UDP packet. (CVE-2006-3468)

Wei Wang of McAfee Avert Labs discovered a buffer overflow in the
sctp_make_abort_user() function of iptables' SCTP module. On computers
which use this module, a local attacker could exploit this to execute
arbitrary code with root privileges. (CVE-2006-3745)

Olof Johansson discovered that the kernel did not disable the 'HID0'
bit on PowerPC 970 processors so that the ATTN instruction was
enabled. A local user could exploit this to crash the kernel. This
flaw only affects the powerpc architecture. (CVE-2006-4093)

The UDF file system does not handle extends larger than 1 GB, but did
not check for this restriction on truncating files. A local user could
exploit this to crash the kernel. (CVE-2006-4145)");

  script_tag(name:"affected", value:"'linux-source-2.6.10, linux-source-2.6.12, linux-source-2.6.15' package(s) on Ubuntu 5.04, Ubuntu 5.10, Ubuntu 6.06.");

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

if(release == "UBUNTU5.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-386", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-686-smp", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-686", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-amd64-generic", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-amd64-k8-smp", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-amd64-k8", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-amd64-xeon", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-hppa32-smp", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-hppa32", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-hppa64-smp", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-hppa64", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-itanium-smp", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-itanium", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-k7-smp", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-k7", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-mckinley-smp", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-mckinley", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-power3-smp", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-power3", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-power4-smp", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-power4", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-powerpc-smp", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-powerpc", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-sparc64-smp", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-sparc64", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-ubuntu-2.6.10", ver:"2.6.10-34.23", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU5.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-386", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-686-smp", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-686", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-generic", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-k8-smp", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-k8", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-xeon", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-hppa32-smp", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-hppa32", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-hppa64-smp", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-hppa64", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-iseries-smp", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-itanium-smp", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-itanium", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-k7-smp", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-k7", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-mckinley-smp", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-mckinley", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-powerpc-smp", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-powerpc", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-powerpc64-smp", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-sparc64-smp", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-sparc64", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-ubuntu-2.6.12", ver:"2.6.12-10.39", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-386", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-686", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-amd64-generic", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-amd64-k8", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-amd64-server", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-amd64-xeon", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-hppa32-smp", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-hppa32", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-hppa64-smp", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-hppa64", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-itanium-smp", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-itanium", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-k7", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-mckinley-smp", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-mckinley", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-powerpc-smp", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-powerpc", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-powerpc64-smp", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-server-bigiron", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-server", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-sparc64-smp", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-sparc64", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-2.6.15", ver:"2.6.15-26.47", rls:"UBUNTU6.06 LTS"))) {
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
