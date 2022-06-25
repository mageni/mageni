###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_486_1.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for linux-source-2.6.17 vulnerabilities USN-486-1
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
tag_insight = "The compat_sys_mount function allowed local users to cause a denial of
  service when mounting a smbfs filesystem in compatibility mode.
  (CVE-2006-7203)

  The Omnikey CardMan 4040 driver (cm4040_cs) did not limit the size of
  buffers passed to read() and write(). A local attacker could exploit
  this to execute arbitrary code with kernel privileges. (CVE-2007-0005)
  
  Due to a variable handling flaw in the  ipv6_getsockopt_sticky()
  function a local attacker could exploit the getsockopt() calls to
  read arbitrary kernel memory. This could disclose sensitive data.
  (CVE-2007-1000)
  
  Ilja van Sprundel discovered that Bluetooth setsockopt calls could leak
  kernel memory contents via an uninitialized stack buffer.  A local
  attacker could exploit this flaw to view sensitive kernel information.
  (CVE-2007-1353)
  
  A flaw was discovered in the handling of netlink messages.  Local
  attackers could cause infinite recursion leading to a denial of service.
  (CVE-2007-1861)
  
  A flaw was discovered in the IPv6 stack's handling of type 0 route
  headers.  By sending a specially crafted IPv6 packet, a remote attacker
  could cause a denial of service between two IPv6 hosts. (CVE-2007-2242)
  
  The random number generator was hashing a subset of the available
  entropy, leading to slightly less random numbers. Additionally, systems
  without an entropy source would be seeded with the same inputs at boot
  time, leading to a repeatable series of random numbers. (CVE-2007-2453)
  
  A flaw was discovered in the PPP over Ethernet implementation.  Local
  attackers could manipulate ioctls and cause kernel memory consumption
  leading to a denial of service. (CVE-2007-2525)
  
  An integer underflow was discovered in the cpuset filesystem.  If mounted,
  local attackers could obtain kernel memory using large file offsets
  while reading the tasks file. This could disclose sensitive data.
  (CVE-2007-2875)
  
  Vilmos Nebehaj discovered that the SCTP netfilter code did not correctly
  validate certain states.  A remote attacker could send a specially
  crafted packet causing a denial of service. (CVE-2007-2876)
  
  Luca Tettamanti discovered a flaw in the VFAT compat ioctls on 64-bit
  systems.  A local attacker could corrupt a kernel_dirent struct and
  cause a denial of service. (CVE-2007-2878)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-486-1";
tag_affected = "linux-source-2.6.17 vulnerabilities on Ubuntu 6.10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-486-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.309666");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:55:18 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2006-7203", "CVE-2007-0005", "CVE-2007-1000", "CVE-2007-1353", "CVE-2007-1861", "CVE-2007-2242", "CVE-2007-2453", "CVE-2007-2525", "CVE-2007-2875", "CVE-2007-2876", "CVE-2007-2878");
  script_name( "Ubuntu Update for linux-source-2.6.17 vulnerabilities USN-486-1");

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

if(release == "UBUNTU6.10")
{

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.17-12-386_2.6.17.1-12.39", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.17-12-generic_2.6.17.1-12.39", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.17-12-server-bigiron_2.6.17.1-12.39", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.17-12-server_2.6.17.1-12.39", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.17-12_2.6.17.1-12.39", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.17-12-386_2.6.17.1-12.39", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.17-12-generic_2.6.17.1-12.39", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.17-12-server-bigiron_2.6.17.1-12.39", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.17-12-server_2.6.17.1-12.39", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.17-12-386_2.6.17.1-12.39", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.17-12-generic_2.6.17.1-12.39", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.17-12-server-bigiron_2.6.17.1-12.39", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.17-12-server_2.6.17.1-12.39", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-kdump", ver:"2.6.17.1-12.39", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.17.1-12.39", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-doc", ver:"2.6.17_2.6.17.1-12.39", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-kernel-devel", ver:"2.6.17.1-12.39", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-source", ver:"2.6.17_2.6.17.1-12.39", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
