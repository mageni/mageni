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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2018.3583.2");
  script_cve_id("CVE-2017-0750", "CVE-2017-0861", "CVE-2017-1000407", "CVE-2017-12153", "CVE-2017-12190", "CVE-2017-12192", "CVE-2017-14051", "CVE-2017-14140", "CVE-2017-14156", "CVE-2017-14489", "CVE-2017-15102", "CVE-2017-15115", "CVE-2017-15274", "CVE-2017-15868", "CVE-2017-16525", "CVE-2017-17450", "CVE-2017-17806", "CVE-2017-18017", "CVE-2017-5669", "CVE-2017-7542", "CVE-2017-7889", "CVE-2017-8824", "CVE-2018-5333", "CVE-2018-5344");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-22 20:40:00 +0000 (Fri, 22 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-3583-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3583-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3583-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-trusty' package(s) announced via the USN-3583-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3583-1 fixed vulnerabilities in the Linux kernel for Ubuntu 14.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 14.04 LTS for Ubuntu
12.04 ESM.

It was discovered that an out-of-bounds write vulnerability existed in the
Flash-Friendly File System (f2fs) in the Linux kernel. An attacker could
construct a malicious file system that, when mounted, could cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2017-0750)

It was discovered that a race condition leading to a use-after-free
vulnerability existed in the ALSA PCM subsystem of the Linux kernel. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2017-0861)

It was discovered that the KVM implementation in the Linux kernel allowed
passthrough of the diagnostic I/O port 0x80. An attacker in a guest VM
could use this to cause a denial of service (system crash) in the host OS.
(CVE-2017-1000407)

Bo Zhang discovered that the netlink wireless configuration interface in
the Linux kernel did not properly validate attributes when handling certain
requests. A local attacker with the CAP_NET_ADMIN could use this to cause a
denial of service (system crash). (CVE-2017-12153)

Vitaly Mayatskikh discovered that the SCSI subsystem in the Linux kernel
did not properly track reference counts when merging buffers. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2017-12190)

It was discovered that the key management subsystem in the Linux kernel did
not properly restrict key reads on negatively instantiated keys. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2017-12192)

It was discovered that an integer overflow existed in the sysfs interface
for the QLogic 24xx+ series SCSI driver in the Linux kernel. A local
privileged attacker could use this to cause a denial of service (system
crash). (CVE-2017-14051)

Otto Ebeling discovered that the memory manager in the Linux kernel did not
properly check the effective UID in some situations. A local attacker could
use this to expose sensitive information. (CVE-2017-14140)

It was discovered that the ATI Radeon framebuffer driver in the Linux
kernel did not properly initialize a data structure returned to user space.
A local attacker could use this to expose sensitive information (kernel
memory). (CVE-2017-14156)

ChunYu Wang discovered that the iSCSI transport implementation in the Linux
kernel did not properly validate data structures. A local attacker could
use this to cause a denial of service (system crash). (CVE-2017-14489)

James Patrick-Evans discovered a race condition in the LEGO USB Infrared
Tower driver in the Linux kernel. A physically proximate attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-lts-trusty' package(s) on Ubuntu 12.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-142-generic-lpae", ver:"3.13.0-142.191~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-142-generic", ver:"3.13.0-142.191~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-lts-trusty", ver:"3.13.0.142.133", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-trusty", ver:"3.13.0.142.133", rls:"UBUNTU12.04 LTS"))) {
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
