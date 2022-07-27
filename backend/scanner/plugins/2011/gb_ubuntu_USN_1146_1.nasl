###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1146_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for linux USN-1146-1
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1146-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840676");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-06-10 16:29:51 +0200 (Fri, 10 Jun 2011)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-4655", "CVE-2010-4656", "CVE-2011-0463", "CVE-2011-0695", "CVE-2011-0712", "CVE-2011-1012", "CVE-2011-1017", "CVE-2011-1593");
  script_name("Ubuntu Update for linux USN-1146-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU8\.04 LTS");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1146-1");
  script_tag(name:"affected", value:"linux on Ubuntu 8.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Kees Cook discovered that some ethtool functions did not correctly clear
  heap memory. A local attacker with CAP_NET_ADMIN privileges could exploit
  this to read portions of kernel heap memory, leading to a loss of privacy.
  (CVE-2010-4655)

  Kees Cook discovered that the IOWarrior USB device driver did not correctly
  check certain size fields. A local attacker with physical access could plug
  in a specially crafted USB device to crash the system or potentially gain
  root privileges. (CVE-2010-4656)

  Goldwyn Rodrigues discovered that the OCFS2 filesystem did not correctly
  clear memory when writing certain file holes. A local attacker could
  exploit this to read uninitialized data from the disk, leading to a loss of
  privacy. (CVE-2011-0463)

  Jens Kuehnel discovered that the InfiniBand driver contained a race
  condition. On systems using InfiniBand, a local attacker could send
  specially crafted requests to crash the system, leading to a denial of
  service. (CVE-2011-0695)

  Rafael Dominguez Vega discovered that the caiaq Native Instruments USB
  driver did not correctly validate string lengths. A local attacker with
  physical access could plug in a specially crafted USB device to crash the
  system or potentially gain root privileges. (CVE-2011-0712)

  Timo Warns discovered that LDM partition parsing routines did not correctly
  calculate block counts. A local attacker with physical access could plug in
  a specially crafted block device to crash the system, leading to a denial
  of service. (CVE-2011-1012)

  Timo Warns discovered that the LDM disk partition handling code did not
  correctly handle certain values. By inserting a specially crafted disk
  device, a local attacker could exploit this to gain root privileges.
  (CVE-2011-1017)

  Tavis Ormandy discovered that the pidmap function did not correctly handle
  large requests. A local attacker could exploit this to crash the system,
  leading to a denial of service. (CVE-2011-1593)");
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

if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-386", ver:"2.6.24-29.90", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-generic", ver:"2.6.24-29.90", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-hppa32", ver:"2.6.24-29.90", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-hppa64", ver:"2.6.24-29.90", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-itanium", ver:"2.6.24-29.90", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-lpia", ver:"2.6.24-29.90", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-lpiacompat", ver:"2.6.24-29.90", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-mckinley", ver:"2.6.24-29.90", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-openvz", ver:"2.6.24-29.90", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-powerpc", ver:"2.6.24-29.90", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-powerpc-smp", ver:"2.6.24-29.90", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-powerpc64-smp", ver:"2.6.24-29.90", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-rt", ver:"2.6.24-29.90", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-server", ver:"2.6.24-29.90", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-sparc64", ver:"2.6.24-29.90", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-sparc64-smp", ver:"2.6.24-29.90", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-virtual", ver:"2.6.24-29.90", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.24-29-xen", ver:"2.6.24-29.90", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
