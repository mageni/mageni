###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1080_2.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for linux-ec2 vulnerabilities USN-1080-2
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1080-2/");
  script_oid("1.3.6.1.4.1.25623.1.0.840601");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-03-07 06:45:55 +0100 (Mon, 07 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-3865", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-4248", "CVE-2010-4343", "CVE-2010-4346", "CVE-2010-4526", "CVE-2010-4527", "CVE-2010-4649", "CVE-2011-1044");
  script_name("Ubuntu Update for linux-ec2 vulnerabilities USN-1080-2");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04 LTS");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1080-2");
  script_tag(name:"affected", value:"linux-ec2 vulnerabilities on Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"USN-1080-1 fixed vulnerabilities in the Linux kernel. This update provides
  the corresponding updates for the Linux kernel for use with EC2.

  Original advisory details:

  Thomas Pollet discovered that the RDS network protocol did not check
  certain iovec buffers. A local attacker could exploit this to crash the
  system or possibly execute arbitrary code as the root user. (CVE-2010-3865)

  Vasiliy Kulikov discovered that the Linux kernel X.25 implementation did
  not correctly clear kernel memory. A local attacker could exploit this to
  read kernel stack memory, leading to a loss of privacy. (CVE-2010-3875)

  Vasiliy Kulikov discovered that the Linux kernel sockets implementation did
  not properly initialize certain structures. A local attacker could exploit
  this to read kernel stack memory, leading to a loss of privacy.
  (CVE-2010-3876)

  Vasiliy Kulikov discovered that the TIPC interface did not correctly
  initialize certain structures. A local attacker could exploit this to read
  kernel stack memory, leading to a loss of privacy. (CVE-2010-3877)

  Nelson Elhage discovered that the Linux kernel IPv4 implementation did not
  properly audit certain bytecodes in netlink messages. A local attacker
  could exploit this to cause the kernel to hang, leading to a denial of
  service. (CVE-2010-3880)

  It was discovered that multithreaded exec did not handle CPU timers
  correctly. A local attacker could exploit this to crash the system, leading
  to a denial of service. (CVE-2010-4248)

  Krishna Gudipati discovered that the bfa adapter driver did not correctly
  initialize certain structures. A local attacker could read files in /sys to
  crash the system, leading to a denial of service. (CVE-2010-4343)

  Tavis Ormandy discovered that the install_special_mapping function could
  bypass the mmap_min_addr restriction. A local attacker could exploit this
  to mmap 4096 bytes below the mmap_min_addr area, possibly improving the
  chances of performing NULL pointer dereference attacks. (CVE-2010-4346)

  It was discovered that the ICMP stack did not correctly handle certain
  unreachable messages. If a remote attacker were able to acquire a socket
  lock, they could send specially crafted traffic that would crash the
  system, leading to a denial of service. (CVE-2010-4526)

  Dan Rosenberg discovered that the OSS subsystem did not handle name
  termination correctly. A local attacker could exploit this crash the system
  or gain root privileges. (CVE-2010-4527)

  Dan Carpenter discovered that the Infiniband driver did not correctly
  handle certain requests. A local user could exploit this to crash the
  system or potentially gain root privileges. (CVE-2010-4649, CVE-2011-1044)");
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

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-313-ec2", ver:"2.6.32-313.26", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-313-ec2", ver:"2.6.32-313.26", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-ec2-doc", ver:"2.6.32-313.26", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-ec2-source-2.6.32", ver:"2.6.32-313.26", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-313", ver:"2.6.32-313.26", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
