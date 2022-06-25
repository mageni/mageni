###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for qemu USN-2974-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842747");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-05-17 13:39:47 +0200 (Tue, 17 May 2016)");
  script_cve_id("CVE-2016-2391", "CVE-2016-2392", "CVE-2016-2538", "CVE-2016-2841",
		"CVE-2016-2857", "CVE-2016-2858", "CVE-2016-3710", "CVE-2016-3712",
		"CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for qemu USN-2974-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Zuozhi Fzz discovered that QEMU incorrectly
  handled USB OHCI emulation support. A privileged attacker inside the guest
  could use this issue to cause QEMU to crash, resulting in a denial of service.
  (CVE-2016-2391)

  Qinghao Tang discovered that QEMU incorrectly handled USB Net emulation
  support. A privileged attacker inside the guest could use this issue to
  cause QEMU to crash, resulting in a denial of service. (CVE-2016-2392)

  Qinghao Tang discovered that QEMU incorrectly handled USB Net emulation
  support. A privileged attacker inside the guest could use this issue to
  cause QEMU to crash, resulting in a denial of service, or possibly leak
  host memory bytes. (CVE-2016-2538)

  Hongke Yang discovered that QEMU incorrectly handled NE2000 emulation
  support. A privileged attacker inside the guest could use this issue to
  cause QEMU to crash, resulting in a denial of service. (CVE-2016-2841)

  Ling Liu discovered that QEMU incorrectly handled IP checksum routines. An
  attacker inside the guest could use this issue to cause QEMU to crash,
  resulting in a denial of service, or possibly leak host memory bytes.
  (CVE-2016-2857)

  It was discovered that QEMU incorrectly handled the PRNG back-end support.
  An attacker inside the guest could use this issue to cause QEMU to crash,
  resulting in a denial of service. This issue only applied to Ubuntu 14.04
  LTS, Ubuntu 15.10 and Ubuntu 16.04 LTS. (CVE-2016-2858)

  Wei Xiao and Qinghao Tang discovered that QEMU incorrectly handled access
  in the VGA module. A privileged attacker inside the guest could use this
  issue to cause QEMU to crash, resulting in a denial of service, or possibly
  execute arbitrary code on the host. In the default installation, when QEMU
  is used with libvirt, attackers would be isolated by the libvirt AppArmor
  profile. (CVE-2016-3710)

  Zuozhi Fzz discovered that QEMU incorrectly handled access in the VGA
  module. A privileged attacker inside the guest could use this issue to
  cause QEMU to crash, resulting in a denial of service, or possibly
  execute arbitrary code on the host. In the default installation, when QEMU
  is used with libvirt, attackers would be isolated by the libvirt AppArmor
  profile. (CVE-2016-3712)

  Oleksandr Bazhaniuk discovered that QEMU incorrectly handled Luminary
  Micro Stellaris ethernet controller emulation. A remote attacker could use
  this issue to cause QEMU to crash, resulting in a denial of service.
  (CVE-2016-4001)

  Oleksandr Bazhaniuk discovered that QEMU incorrectly handled MIPSnet
  controller emulation. A remote attacker could use this issue to cause QEMU
  to crash, resulting in a denial of ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"qemu on Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2974-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS|15\.10)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"qemu-system", ver:"2.0.0+dfsg-2ubuntu1.24", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-aarch64", ver:"2.0.0+dfsg-2ubuntu1.24", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-arm", ver:"2.0.0+dfsg-2ubuntu1.24", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-mips", ver:"2.0.0+dfsg-2ubuntu1.24", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-misc", ver:"2.0.0+dfsg-2ubuntu1.24", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"2.0.0+dfsg-2ubuntu1.24", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"2.0.0+dfsg-2ubuntu1.24", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-x86", ver:"2.0.0+dfsg-2ubuntu1.24", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"qemu-kvm", ver:"1.0+noroms-0ubuntu14.28", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU15.10")
{

  if ((res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.3+dfsg-5ubuntu9.4", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-aarch64", ver:"1:2.3+dfsg-5ubuntu9.4", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.3+dfsg-5ubuntu9.4", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.3+dfsg-5ubuntu9.4", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.3+dfsg-5ubuntu9.4", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.3+dfsg-5ubuntu9.4", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.3+dfsg-5ubuntu9.4", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.3+dfsg-5ubuntu9.4", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
