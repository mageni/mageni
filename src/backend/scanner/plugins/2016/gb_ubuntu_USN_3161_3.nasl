###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-raspi2 USN-3161-3
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
  script_oid("1.3.6.1.4.1.25623.1.0.843001");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-12-21 05:45:34 +0100 (Wed, 21 Dec 2016)");
  script_cve_id("CVE-2015-8964", "CVE-2016-4568", "CVE-2016-6213", "CVE-2016-7042",
		"CVE-2016-7097", "CVE-2016-7425", "CVE-2016-8630", "CVE-2016-8633",
		"CVE-2016-8645", "CVE-2016-8658", "CVE-2016-9178", "CVE-2016-9555");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux-raspi2 USN-3161-3");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-raspi2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Tilman Schmidt and Sasha Levin discovered a
  use-after-free condition in the TTY implementation in the Linux kernel. A local
  attacker could use this to expose sensitive information (kernel memory).
  (CVE-2015-8964)

It was discovered that the Video For Linux Two (v4l2) implementation in the
Linux kernel did not properly handle multiple planes when processing a
VIDIOC_DQBUF ioctl(). A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2016-4568)

CAI Qian discovered that shared bind mounts in a mount namespace
exponentially added entries without restriction to the Linux kernel's mount
table. A local attacker could use this to cause a denial of service (system
crash). (CVE-2016-6213)

Ondrej Kozina discovered that the keyring interface in the Linux kernel
contained a buffer overflow when displaying timeout events via the
/proc/keys interface. A local attacker could use this to cause a denial of
service (system crash). (CVE-2016-7042)

Andreas Gruenbacher and Jan Kara discovered that the filesystem
implementation in the Linux kernel did not clear the setgid bit during a
setxattr call. A local attacker could use this to possibly elevate group
privileges. (CVE-2016-7097)

Marco Grassi discovered that the driver for Areca RAID Controllers in the
Linux kernel did not properly validate control messages. A local attacker
could use this to cause a denial of service (system crash) or possibly gain
privileges. (CVE-2016-7425)

It was discovered that the KVM implementation for x86/x86_64 in the Linux
kernel could dereference a null pointer. An attacker in a guest virtual
machine could use this to cause a denial of service (system crash) in the
KVM host. (CVE-2016-8630)

Eyal Itkin discovered that the IP over IEEE 1394 (FireWire) implementation
in the Linux kernel contained a buffer overflow when handling fragmented
packets. A remote attacker could use this to possibly execute arbitrary
code with administrative privileges. (CVE-2016-8633)

Marco Grassi discovered that the TCP implementation in the Linux kernel
mishandles socket buffer (skb) truncation. A local attacker could use this
to cause a denial of service (system crash). (CVE-2016-8645)

Daxing Guo discovered a stack-based buffer overflow in the Broadcom
IEEE802.11n FullMAC driver in the Linux kernel. A local attacker could use
this to cause a denial of service (system crash) or possibly gain
privileges. (CVE-2016-8658)

It was discovered that an information leak existed in __get_user_asm_ex()
in the Linux kernel. A local attacker could use this to expose sensitive
information. ( ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"linux-raspi2 on Ubuntu 16.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3161-3/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04 LTS");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-1038-raspi2", ver:"4.4.0-1038.45", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"4.4.0.1038.37", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
