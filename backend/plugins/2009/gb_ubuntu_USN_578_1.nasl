###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_578_1.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for linux-source-2.6.15 vulnerabilities USN-578-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "The minix filesystem did not properly validate certain filesystem
  values. If a local attacker could trick the system into attempting
  to mount a corrupted minix filesystem, the kernel could be made to
  hang for long periods of time, resulting in a denial of service.
  (CVE-2006-6058)

  Alexander Schulze discovered that the skge driver does not properly
  use the spin_lock and spin_unlock functions. Remote attackers could
  exploit this by sending a flood of network traffic and cause a denial
  of service (crash). (CVE-2006-7229)
  
  Hugh Dickins discovered that hugetlbfs performed certain prio_tree
  calculations using HPAGE_SIZE instead of PAGE_SIZE. A local user
  could exploit this and cause a denial of service via kernel panic.
  (CVE-2007-4133)
  
  Chris Evans discovered an issue with certain drivers that use the
  ieee80211_rx function. Remote attackers could send a crafted 802.11
  frame and cause a denial of service via crash. (CVE-2007-4997)
  
  Alex Smith discovered an issue with the pwc driver for certain webcam
  devices. A local user with physical access to the system could remove
  the device while a userspace application had it open and cause the USB
  subsystem to block. (CVE-2007-5093)
  
  Scott James Remnant discovered a coding error in ptrace. Local users
  could exploit this and cause the kernel to enter an infinite loop.
  (CVE-2007-5500)
  
  Venustech AD-LAB discovered a buffer overflow in the isdn net
  subsystem. This issue is exploitable by local users via crafted input
  to the isdn_ioctl function. (CVE-2007-6063)
  
  It was discovered that the isdn subsystem did not properly check for
  NULL termination when performing ioctl handling. A local user could
  exploit this to cause a denial of service. (CVE-2007-6151)
  
  Blake Frantz discovered that when a root process overwrote an existing
  core file, the resulting core file retained the previous core file's
  ownership. Local users could exploit this to gain access to sensitive
  information. (CVE-2007-6206)
  
  Hugh Dickins discovered the when using the tmpfs filesystem, under
  rare circumstances, a kernel page may be improperly cleared. A local
  user may be able to exploit this and read sensitive kernel data or
  cause a denial of service via crash. (CVE-2007-6417)
  
  Bill Roman discovered that the VFS subsystem did not properly check
  access modes. A local user may be able to gain removal privileges
  on directories. (CVE-2008-0001)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-578-1";
tag_affected = "linux-source-2.6.15 vulnerabilities on Ubuntu 6.06 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-578-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.306279");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2006-6058", "CVE-2006-7229", "CVE-2007-4133", "CVE-2007-4997", "CVE-2007-5093", "CVE-2007-5500", "CVE-2007-6063", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6417", "CVE-2008-0001");
  script_name( "Ubuntu Update for linux-source-2.6.15 vulnerabilities USN-578-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-51-386_2.6.15-51.66", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-51-686_2.6.15-51.66", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-51-k7_2.6.15-51.66", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-51-server-bigiron_2.6.15-51.66", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-51-server_2.6.15-51.66", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-51_2.6.15-51.66", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-51-386_2.6.15-51.66", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-51-686_2.6.15-51.66", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-51-k7_2.6.15-51.66", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-51-server-bigiron_2.6.15-51.66", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-51-server_2.6.15-51.66", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-doc", ver:"2.6.15_2.6.15-51.66", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-kernel-devel", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-source", ver:"2.6.15_2.6.15-51.66", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
