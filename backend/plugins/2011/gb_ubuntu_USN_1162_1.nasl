###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1162_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for linux-mvl-dove USN-1162-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1162-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840696");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-07-08 16:31:28 +0200 (Fri, 08 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-4243", "CVE-2010-4263", "CVE-2010-4342", "CVE-2010-4529", "CVE-2010-4565", "CVE-2011-0463", "CVE-2011-0695", "CVE-2011-0711", "CVE-2011-0726", "CVE-2011-1013", "CVE-2011-1016", "CVE-2011-1017", "CVE-2011-1019", "CVE-2011-1090", "CVE-2011-1163", "CVE-2011-1182", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1593", "CVE-2011-1598", "CVE-2011-1748", "CVE-2011-1745", "CVE-2011-2022", "CVE-2011-1746", "CVE-2011-1747");
  script_name("Ubuntu Update for linux-mvl-dove USN-1162-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04 LTS");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1162-1");
  script_tag(name:"affected", value:"linux-mvl-dove on Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Brad Spengler discovered that the kernel did not correctly account for
  userspace memory allocations during exec() calls. A local attacker could
  exploit this to consume all system memory, leading to a denial of service.
  (CVE-2010-4243)

  Alexander Duyck discovered that the Intel Gigabit Ethernet driver did not
  correctly handle certain configurations. If such a device was configured
  without VLANs, a remote attacker could crash the system, leading to a
  denial of service. (CVE-2010-4263)

  Nelson Elhage discovered that Econet did not correctly handle AUN packets
  over UDP. A local attacker could send specially crafted traffic to crash
  the system, leading to a denial of service. (CVE-2010-4342)

  Dan Rosenberg discovered that IRDA did not correctly check the size of
  buffers. On non-x86 systems, a local attacker could exploit this to read
  kernel heap memory, leading to a loss of privacy. (CVE-2010-4529)

  Dan Rosenburg discovered that the CAN subsystem leaked kernel addresses
  into the /proc filesystem. A local attacker could use this to increase the
  chances of a successful memory corruption exploit. (CVE-2010-4565)

  Goldwyn Rodrigues discovered that the OCFS2 filesystem did not correctly
  clear memory when writing certain file holes. A local attacker could
  exploit this to read uninitialized data from the disk, leading to a loss of
  privacy. (CVE-2011-0463)

  Jens Kuehnel discovered that the InfiniBand driver contained a race
  condition. On systems using InfiniBand, a local attacker could send
  specially crafted requests to crash the system, leading to a denial of
  service. (CVE-2011-0695)

  Dan Rosenberg discovered that XFS did not correctly initialize memory. A
  local attacker could make crafted ioctl calls to leak portions of kernel
  stack memory, leading to a loss of privacy. (CVE-2011-0711)

  Kees Cook reported that /proc/pid/stat did not correctly filter certain
  memory locations. A local attacker could determine the memory layout of
  processes in an attempt to increase the chances of a successful memory
  corruption exploit. (CVE-2011-0726)

  Matthiew Herrb discovered that the drm modeset interface did not correctly
  handle a signed comparison. A local attacker could exploit this to crash
  the system or possibly gain root privileges. (CVE-2011-1013)

  Marek Olsaak discovered that the Radeon GPU drivers did not correctly
  validate certain registers. On systems with specific hardware, a local
  attacker could exploit this to write to arbitrary video memory.
  (CVE-2011-1016)

  Timo Warns discovered that t ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-217-dove", ver:"2.6.32-217.34", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
