###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1167_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for linux USN-1167-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1167-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840699");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-07-18 15:23:56 +0200 (Mon, 18 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2010-3859", "CVE-2010-3874", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-4158", "CVE-2010-4162", "CVE-2010-4163", "CVE-2010-4668", "CVE-2010-4164", "CVE-2010-4165", "CVE-2010-4169", "CVE-2010-4175", "CVE-2010-4243", "CVE-2010-4248", "CVE-2010-4249", "CVE-2010-4256", "CVE-2010-4258", "CVE-2010-4342", "CVE-2010-4346", "CVE-2010-4527", "CVE-2010-4529", "CVE-2010-4565", "CVE-2010-4649", "CVE-2011-1044", "CVE-2011-0463", "CVE-2011-0521", "CVE-2011-0695", "CVE-2011-0711", "CVE-2011-0712", "CVE-2011-0726", "CVE-2011-0999", "CVE-2011-1010", "CVE-2011-1012", "CVE-2011-1013", "CVE-2011-1016", "CVE-2011-1017", "CVE-2011-1019", "CVE-2011-1076", "CVE-2011-1082", "CVE-2011-1083", "CVE-2011-1090", "CVE-2011-1163", "CVE-2011-1169", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-2534", "CVE-2011-1173", "CVE-2011-1182", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1593", "CVE-2011-1598", "CVE-2011-1748", "CVE-2011-1745", "CVE-2011-2022", "CVE-2011-1746", "CVE-2011-1747", "CVE-2011-1770");
  script_name("Ubuntu Update for linux USN-1167-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.04");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1167-1");
  script_tag(name:"affected", value:"linux on Ubuntu 11.04");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Dan Rosenberg discovered that the Linux kernel TIPC implementation
  contained multiple integer signedness errors. A local attacker could
  exploit this to gain root privileges. (CVE-2010-3859)

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

  Dan Rosenberg discovered that the socket filters did not correctly
  initialize structure memory. A local attacker could create malicious
  filters to read portions of kernel stack memory, leading to a loss of
  privacy. (CVE-2010-4158)

  Dan Rosenberg discovered that certain iovec operations did not calculate
  page counts correctly. A local attacker could exploit this to crash the
  system, leading to a denial of service. (CVE-2010-4162)

  Dan Rosenberg discovered that the SCSI subsystem did not correctly validate
  iov segments. A local attacker with access to a SCSI device could send
  specially crafted requests to crash the system, leading to a denial of
  service. (CVE-2010-4163, CVE-2010-4668)

  Dan Rosenberg discovered multiple flaws in the X.25 facilities parsing. If
  a system was using X.25, a remote attacker could exploit this to crash the
  system, leading to a denial of service. (CVE-2010-4164)

  Steve Chen discovered that setsockopt did not correctly check MSS values. A
  local attacker could make a specially crafted socket call to crash the
  system, leading to a denial of service. (CVE-2010-4165)

  Dave Jones discovered that the mprotect system call did not correctly
  handle merged VMAs. A  ...

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

if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-10-generic", ver:"2.6.38-10.46", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-10-generic-pae", ver:"2.6.38-10.46", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-10-omap", ver:"2.6.38-10.46", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-10-powerpc", ver:"2.6.38-10.46", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-10-powerpc-smp", ver:"2.6.38-10.46", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-10-powerpc64-smp", ver:"2.6.38-10.46", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-10-server", ver:"2.6.38-10.46", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-10-versatile", ver:"2.6.38-10.46", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-10-virtual", ver:"2.6.38-10.46", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
