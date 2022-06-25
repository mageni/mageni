###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for qemu USN-3268-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843143");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-04-26 06:39:36 +0200 (Wed, 26 Apr 2017)");
  script_cve_id("CVE-2016-10028", "CVE-2016-8667", "CVE-2016-9602", "CVE-2016-9603",
                "CVE-2016-9908", "CVE-2016-9912", "CVE-2017-5552", "CVE-2017-5578",
                "CVE-2016-9914", "CVE-2017-5987", "CVE-2017-6505");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for qemu USN-3268-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Zhenhao Hong discovered that QEMU
incorrectly handled the Virtio GPU device. An attacker inside the guest could
use this issue to cause QEMU to crash, resulting in a denial of service.
(CVE-2016-10028)

It was discovered that QEMU incorrectly handled the JAZZ RC4030 device. A
privileged attacker inside the guest could use this issue to cause QEMU to
crash, resulting in a denial of service. (CVE-2016-8667)

Jann Horn discovered that QEMU incorrectly handled VirtFS directory
sharing. A privileged attacker inside the guest could use this issue to
access files on the host file system outside of the shared directory and
possibly escalate their privileges. In the default installation, when QEMU
is used with libvirt, attackers would be isolated by the libvirt AppArmor
profile. (CVE-2016-9602)

Gerd Hoffmann discovered that QEMU incorrectly handled the Cirrus VGA
device when being used with a VNC connection. A privileged attacker inside
the guest could use this issue to cause QEMU to crash, resulting in a
denial of service, or possibly execute arbitrary code on the host. In the
default installation, when QEMU is used with libvirt, attackers would be
isolated by the libvirt AppArmor profile. (CVE-2016-9603)

Li Qiang discovered that QEMU incorrectly handled the Virtio GPU device. An
attacker inside the guest could use this issue to cause QEMU to leak
contents of host memory. (CVE-2016-9908)

Li Qiang discovered that QEMU incorrectly handled the Virtio GPU device. An
attacker inside the guest could use this issue to cause QEMU to crash,
resulting in a denial of service. (CVE-2016-9912, CVE-2017-5552,
CVE-2017-5578)

Li Qiang discovered that QEMU incorrectly handled VirtFS directory sharing.
A privileged attacker inside the guest could use this issue to cause QEMU
to crash, resulting in a denial of service. (CVE-2016-9914)

Jiang Xin and Wjjzhang discovered that QEMU incorrectly handled SDHCI
device emulation. A privileged attacker inside the guest could use this
issue to cause QEMU to crash, resulting in a denial of service.
(CVE-2017-5987)

Li Qiang discovered that QEMU incorrectly handled USB OHCI controller
emulation. A privileged attacker inside the guest could use this issue to
cause QEMU to hang, resulting in a denial of service. (CVE-2017-6505)");
  script_tag(name:"affected", value:"qemu on Ubuntu 17.04");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3268-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU17\.04");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU17.04")
{

  if ((res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.8+dfsg-3ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-aarch64", ver:"1:2.8+dfsg-3ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.8+dfsg-3ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.8+dfsg-3ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.8+dfsg-3ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.8+dfsg-3ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-s390x", ver:"1:2.8+dfsg-3ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.8+dfsg-3ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.8+dfsg-3ubuntu2.1", rls:"UBUNTU17.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
