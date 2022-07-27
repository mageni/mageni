###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-raspi2 USN-3004-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842787");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-06-11 05:25:42 +0200 (Sat, 11 Jun 2016)");
  script_cve_id("CVE-2016-2117", "CVE-2016-1583", "CVE-2015-4004", "CVE-2016-2187", "CVE-2016-3672", "CVE-2016-3951", "CVE-2016-3955", "CVE-2016-3961", "CVE-2016-4485", "CVE-2016-4486", "CVE-2016-4565", "CVE-2016-4581");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux-raspi2 USN-3004-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-raspi2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Justin Yackoski discovered that the Atheros L2 Ethernet Driver in the Linux
kernel incorrectly enables scatter/gather I/O. A remote attacker could use
this to obtain potentially sensitive information from kernel memory.
(CVE-2016-2117)

Jann Horn discovered that eCryptfs improperly attempted to use the mmap()
handler of a lower filesystem that did not implement one, causing a
recursive page fault to occur. A local unprivileged attacker could use to
cause a denial of service (system crash) or possibly execute arbitrary code
with administrative privileges. (CVE-2016-1583)

Jason A. Donenfeld discovered multiple out-of-bounds reads in the OZMO USB
over wifi device drivers in the Linux kernel. A remote attacker could use
this to cause a denial of service (system crash) or obtain potentially
sensitive information from kernel memory. (CVE-2015-4004)

Ralf Spenneberg discovered that the Linux kernel's GTCO digitizer USB
device driver did not properly validate endpoint descriptors. An attacker
with physical access could use this to cause a denial of service (system
crash). (CVE-2016-2187)

Hector Marco and Ismael Ripoll discovered that the Linux kernel would
improperly disable Address Space Layout Randomization (ASLR) for x86
processes running in 32 bit mode if stack-consumption resource limits were
disabled. A local attacker could use this to make it easier to exploit an
existing vulnerability in a setuid/setgid program. (CVE-2016-3672)

Andrey Konovalov discovered that the CDC Network Control Model USB driver
in the Linux kernel did not cancel work events queued if a later error
occurred, resulting in a use-after-free. An attacker with physical access
could use this to cause a denial of service (system crash). (CVE-2016-3951)

It was discovered that an out-of-bounds write could occur when handling
incoming packets in the USB/IP implementation in the Linux kernel. A remote
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2016-3955)

Vitaly Kuznetsov discovered that the Linux kernel did not properly suppress
hugetlbfs support in X86 paravirtualized guests. An attacker in the guest
OS could cause a denial of service (guest system crash). (CVE-2016-3961)

Kangjie Lu discovered an information leak in the ANSI/IEEE 802.2 LLC type 2
Support implementations in the Linux kernel. A local attacker could use
this to obtain potentially sensitive information from kernel memory.
(CVE-2016-4485)

Kangjie Lu discovered an information leak in the routing netlink socket
interface (rtnetlink) implementation in the Linux kernel. A local attacker
could use ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"linux-raspi2 on Ubuntu 15.10");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3004-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU15\.10");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU15.10")
{

  if ((res = isdpkgvuln(pkg:"linux-image-4.2.0-1031-raspi2", ver:"4.2.0-1031.41", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}