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
  script_oid("1.3.6.1.4.1.25623.1.0.845329");
  script_version("2022-04-29T06:36:55+0000");
  script_cve_id("CVE-2022-1015", "CVE-2022-0494", "CVE-2022-0854", "CVE-2022-1011", "CVE-2022-1016", "CVE-2022-1048", "CVE-2022-24958", "CVE-2022-26490", "CVE-2022-26966", "CVE-2022-27223", "CVE-2022-28356");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-29 10:20:12 +0000 (Fri, 29 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-21 01:00:28 +0000 (Thu, 21 Apr 2022)");
  script_name("Ubuntu: Security Advisory for linux-oem-5.14 (USN-5381-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04 LTS");

  script_xref(name:"Advisory-ID", value:"USN-5381-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2022-April/006512.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-5.14'
  package(s) announced via the USN-5381-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"David Bouman discovered that the netfilter subsystem in the Linux kernel
did not properly validate passed user register indices. A local attacker
could use this to cause a denial of service or possibly execute arbitrary
code. (CVE-2022-1015)

It was discovered that the block layer subsystem in the Linux kernel did
not properly initialize memory in some situations. A privileged local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2022-0494)

It was discovered that the DMA subsystem in the Linux kernel did not
properly ensure bounce buffers were completely overwritten by the DMA
device. A local attacker could use this to expose sensitive information
(kernel memory). (CVE-2022-0854)

Jann Horn discovered that the FUSE file system in the Linux kernel
contained a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2022-1011)

David Bouman discovered that the netfilter subsystem in the Linux kernel
did not initialize memory in some situations. A local attacker could use
this to expose sensitive information (kernel memory). (CVE-2022-1016)

Hu Jiahui discovered that multiple race conditions existed in the Advanced
Linux Sound Architecture (ALSA) framework, leading to use-after-free
vulnerabilities. A local attacker could use these to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2022-1048)

It was discovered that the USB Gadget file system interface in the Linux
kernel contained a use-after-free vulnerability. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2022-24958)

It was discovered that the ST21NFCA NFC driver in the Linux kernel
did not properly validate the size of certain data in EVT_TRANSACTION
events. A physically proximate attacker could use this to cause
a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2022-26490)

It was discovered that the USB SR9700 ethernet device driver for the
Linux kernel did not properly validate the length of requests from
the device. A physically proximate attacker could possibly use this
to expose sensitive information (kernel memory). (CVE-2022-26966)

It was discovered that the Xilinx USB2 device gadget driver in the
Linux kernel did not properly validate endpoint indices from the
host. A physically proximate attacker could possibly use this to
cause a denial of service (system crash). (CVE-2022-27223)

 discovered that the 802.2 LLC type 2 driver in the Linux
kernel did not properly perform reference counting in some error
conditions. A local attacker could use this to cause a denial of
service. (CVE-2022-28356)");

  script_tag(name:"affected", value:"'linux-oem-5.14' package(s) on Ubuntu 20.04 LTS.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.14.0-1033-oem", ver:"5.14.0-1033.36", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04", ver:"5.14.0.1033.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04b", ver:"5.14.0.1033.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04c", ver:"5.14.0.1033.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04d", ver:"5.14.0.1033.30", rls:"UBUNTU20.04 LTS"))) {
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