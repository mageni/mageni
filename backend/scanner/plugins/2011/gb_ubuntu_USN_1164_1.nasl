###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1164_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for linux-fsl-imx51 USN-1164-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1164-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840693");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-07-08 16:31:28 +0200 (Fri, 08 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2010-3865", "CVE-2010-3874", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4082", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4164", "CVE-2010-4248", "CVE-2010-4258", "CVE-2010-4342", "CVE-2010-4346", "CVE-2010-4527", "CVE-2010-4529", "CVE-2010-4565", "CVE-2010-4655", "CVE-2010-4656", "CVE-2011-0463", "CVE-2011-0521", "CVE-2011-0695", "CVE-2011-0711", "CVE-2011-0712", "CVE-2011-1017", "CVE-2011-1182", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1593", "CVE-2011-1745", "CVE-2011-2022", "CVE-2011-1746", "CVE-2011-1747", "CVE-2011-1748");
  script_name("Ubuntu Update for linux-fsl-imx51 USN-1164-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04 LTS");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1164-1");
  script_tag(name:"affected", value:"linux-fsl-imx51 on Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Thomas Pollet discovered that the RDS network protocol did not check
  certain iovec buffers. A local attacker could exploit this to crash the
  system or possibly execute arbitrary code as the root user. (CVE-2010-3865)

  Dan Rosenberg discovered that the CAN protocol on 64bit systems did not
  correctly calculate the size of certain buffers. A local attacker could
  exploit this to crash the system or possibly execute arbitrary code as the
  root user. (CVE-2010-3874)

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

  Dan Rosenberg discovered that the RME Hammerfall DSP audio interface driver
  did not correctly clear kernel memory. A local attacker could exploit this
  to read kernel stack memory, leading to a loss of privacy. (CVE-2010-4080,
  CVE-2010-4081)

  Dan Rosenberg discovered that the VIA video driver did not correctly clear
  kernel memory. A local attacker could exploit this to read kernel stack
  memory, leading to a loss of privacy. (CVE-2010-4082)

  Dan Rosenberg discovered that the semctl syscall did not correctly clear
  kernel memory. A local attacker could exploit this to read kernel stack
  memory, leading to a loss of privacy. (CVE-2010-4083)

  James Bottomley discovered that the ICP vortex storage array controller
  driver did not validate certain sizes. A local attacker on a 64bit system
  could exploit this to crash the kernel, leading to a denial of service.
  (CVE-2010-4157)

  Dan Rosenberg discovered multiple flaws in the X.25 facilities parsing. If
  a system was using X.25, a remote attacker could exploit this to crash the
  system, leading to a denial of service. (CVE-2010-4164)

  It was discovered that multithreaded exec did not handle CPU timers
  c ...

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

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.31-609-imx51", ver:"2.6.31-609.26", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
