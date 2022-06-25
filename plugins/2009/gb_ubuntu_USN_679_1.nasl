###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_679_1.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for linux, linux-source-2.6.15/22 vulnerabilities USN-679-1
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
tag_insight = "It was discovered that the Xen hypervisor block driver did not correctly
  validate requests. A user with root privileges in a guest OS could make a
  malicious IO request with a large number of blocks that would crash the
  host OS, leading to a denial of service. This only affected Ubuntu 7.10.
  (CVE-2007-5498)

  It was discovered the the i915 video driver did not correctly validate
  memory addresses. A local attacker could exploit this to remap memory that
  could cause a system crash, leading to a denial of service. This issue did
  not affect Ubuntu 6.06 and was previous fixed for Ubuntu 7.10 and 8.04 in
  USN-659-1. Ubuntu 8.10 has now been corrected as well. (CVE-2008-3831)
  
  David Watson discovered that the kernel did not correctly strip permissions
  when creating files in setgid directories. A local user could exploit this
  to gain additional group privileges. This issue only affected Ubuntu 6.06.
  (CVE-2008-4210)
  
  Olaf Kirch and Miklos Szeredi discovered that the Linux kernel did
  not correctly reject the &quot;append&quot; flag when handling file splice
  requests. A local attacker could bypass append mode and make changes to
  arbitrary locations in a file. This issue only affected Ubuntu 7.10 and
  8.04. (CVE-2008-4554)
  
  It was discovered that the SCTP stack did not correctly handle INIT-ACK. A
  remote user could exploit this by sending specially crafted SCTP traffic
  which would trigger a crash in the system, leading to a denial of service.
  This issue did not affect Ubuntu 8.10. (CVE-2008-4576)
  
  It was discovered that the SCTP stack did not correctly handle bad packet
  lengths. A remote user could exploit this by sending specially crafted SCTP
  traffic which would trigger a crash in the system, leading to a denial of
  service. This issue did not affect Ubuntu 8.10. (CVE-2008-4618)
  
  Eric Sesterhenn discovered multiple flaws in the HFS+ filesystem. If a
  local user or automated system were tricked into mounting a malicious HFS+
  filesystem, the system could crash, leading to a denial of service.
  (CVE-2008-4933, CVE-2008-4934, CVE-2008-5025)
  
  It was discovered that the Unix Socket handler did not correctly process
  the SCM_RIGHTS message. A local attacker could make a malicious socket
  request that would crash the system, leading to a denial of service.
  (CVE-2008-5029)
  
  It was discovered that the driver for simple i2c audio interfaces did not
  correctly validate certain function pointers. A local user could exploit
  this to gain root privileges or crash the system, leading to a denial of
  service. (CVE-2008-5033)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-679-1";
tag_affected = "linux, linux-source-2.6.15/22 vulnerabilities on Ubuntu 6.06 LTS ,
  Ubuntu 7.10 ,
  Ubuntu 8.04 LTS ,
  Ubuntu 8.10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-679-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.308022");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2007-5498", "CVE-2008-3831", "CVE-2008-4210", "CVE-2008-4554", "CVE-2008-4576", "CVE-2008-4618", "CVE-2008-4933", "CVE-2008-4934", "CVE-2008-5025", "CVE-2008-5029", "CVE-2008-5033");
  script_name( "Ubuntu Update for linux, linux-source-2.6.15/22 vulnerabilities USN-679-1");

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

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.15-53-386_2.6.15-53.11", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.15-53-686_2.6.15-53.11", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.15-53-k7_2.6.15-53.11", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.15-53-server-bigiron_2.6.15-53.11", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.15-53-server_2.6.15-53.11", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-53-386_2.6.15-53.74", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-53-686_2.6.15-53.74", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-53-k7_2.6.15-53.74", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-53-server-bigiron_2.6.15-53.74", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-53-server_2.6.15-53.74", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.15-53_2.6.15-53.74", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-53-386_2.6.15-53.74", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-53-686_2.6.15-53.74", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-53-k7_2.6.15-53.74", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-53-server-bigiron_2.6.15-53.74", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.15-53-server_2.6.15-53.74", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"avm-fritz-kernel-source", ver:"3.11+2.6.15.12-53.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fglrx-kernel-source", ver:"8.25.18+2.6.15.12-53.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-kernel-source", ver:"1.0.8776+2.6.15.12-53.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-legacy-kernel-source", ver:"1.0.7174+2.6.15.12-53.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"avm-fritz-firmware", ver:"2.6.15-53_3.11+2.6.15.12-53.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fglrx-control", ver:"8.25.18+2.6.15.12-53.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.15-53-386_2.6.15.12-53.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.15-53-686_2.6.15.12-53.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.15-53-k7_2.6.15.12-53.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-dev", ver:"1.0.8776+2.6.15.12-53.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-legacy-dev", ver:"1.0.7174+2.6.15.12-53.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-legacy", ver:"1.0.7174+2.6.15.12-53.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx", ver:"1.0.8776+2.6.15.12-53.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xorg-driver-fglrx-dev", ver:"7.0.0-8.25.18+2.6.15.12-53.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xorg-driver-fglrx", ver:"7.0.0-8.25.18+2.6.15.12-53.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-doc", ver:"2.6.15_2.6.15-53.74", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-kernel-devel", ver:"2.6.15-53.74", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-source", ver:"2.6.15_2.6.15-53.74", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules-common", ver:"2.6.15.12-53.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.10")
{

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.27-9-generic_2.6.27-9.5", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.27-9-server_2.6.27-9.5", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-lbm", ver:"2.6.27-9-generic_2.6.27-9.5", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-lbm", ver:"2.6.27-9-server_2.6.27-9.5", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.27-9-generic_2.6.27-9.19", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.27-9-server_2.6.27-9.19", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.27-9-generic_2.6.27-9.19", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.27-9-server_2.6.27-9.19", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.27-9-virtual_2.6.27-9.19", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.27-9.19", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.27-9-generic_2.6.27-9.13", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.27-9-server_2.6.27-9.13", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-doc", ver:"2.6.27_2.6.27-9.19", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.27-9_2.6.27-9.19", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-source", ver:"2.6.27_2.6.27-9.19", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules-common", ver:"2.6.27-9.13", rls:"UBUNTU8.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.24-22-386_2.6.24-22.29", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.24-22-generic_2.6.24-22.29", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.24-22-server_2.6.24-22.29", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.24-22-virtual_2.6.24-22.29", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-lbm", ver:"2.6.24-22-386_2.6.24-22.29", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-lbm", ver:"2.6.24-22-generic_2.6.24-22.29", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-lbm", ver:"2.6.24-22-server_2.6.24-22.29", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-lbm", ver:"2.6.24-22-virtual_2.6.24-22.29", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-lum", ver:"2.6.24-22-386_2.6.24-22.35", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-lum", ver:"2.6.24-22-generic_2.6.24-22.35", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-lum", ver:"2.6.24-22-server_2.6.24-22.35", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-lum", ver:"2.6.24-22-virtual_2.6.24-22.35", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-ubuntu-modules", ver:"2.6.24-22-386_2.6.24-22.35", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-ubuntu-modules", ver:"2.6.24-22-generic_2.6.24-22.35", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-ubuntu-modules", ver:"2.6.24-22-server_2.6.24-22.35", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-ubuntu-modules", ver:"2.6.24-22-virtual_2.6.24-22.35", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.24-22-386_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.24-22-generic_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.24-22-openvz_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.24-22-rt_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.24-22-server_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.24-22-virtual_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.24-22-xen_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.24-22-386_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.24-22-generic_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.24-22-server_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.24-22-virtual_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.24-22-386_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.24-22-generic_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.24-22-server_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.24-22-virtual_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fglrx-kernel-source_8-3+2.6.24.14", ver:"22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.24-22-openvz_2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.24-22-rt_2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.24-22-xen_2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-legacy-dev", ver:"71.86.04+2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-legacy", ver:"71.86.04+2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-kernel-source", ver:"96.43.05+2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-legacy-kernel-source", ver:"71.86.04+2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"avm-fritz-firmware", ver:"2.6.24-22_3.11+2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"avm-fritz-kernel-source", ver:"3.11+2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fglrx-amdcccle", ver:"2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fglrx-control_8-3+2.6.24.14", ver:"22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.24-22-386_2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.24-22-generic_2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.24-22-server_2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-dev", ver:"96.43.05+2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-new-dev", ver:"169.12+2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-new", ver:"169.12+2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx", ver:"96.43.05+2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-new-kernel-source", ver:"169.12+2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xorg-driver-fglrx-dev", ver:"7.1.0-8-3+2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xorg-driver-fglrx", ver:"7.1.0-8-3+2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.24-22-openvz_2.6.24-22.29", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.24-22-rt_2.6.24-22.29", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.24-22-xen_2.6.24-22.29", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-lbm", ver:"2.6.24-22-openvz_2.6.24-22.29", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-lbm", ver:"2.6.24-22-rt_2.6.24-22.29", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-lbm", ver:"2.6.24-22-xen_2.6.24-22.29", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-lum", ver:"2.6.24-22-openvz_2.6.24-22.35", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-lum", ver:"2.6.24-22-rt_2.6.24-22.35", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers-lum", ver:"2.6.24-22-xen_2.6.24-22.35", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-ubuntu-modules", ver:"2.6.24-22-openvz_2.6.24-22.35", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-ubuntu-modules", ver:"2.6.24-22-rt_2.6.24-22.35", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-ubuntu-modules", ver:"2.6.24-22-xen_2.6.24-22.35", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.24-22-openvz_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.24-22-rt_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.24-22-xen_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-doc", ver:"2.6.24_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.24-22_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-kernel-devel", ver:"2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-source", ver:"2.6.24_2.6.24-22.45", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules-common", ver:"2.6.24.14-22.53", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.10")
{

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.22-16-386_2.6.22-16.17", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.22-16-generic_2.6.22-16.17", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.22-16-server_2.6.22-16.17", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.22-16-386_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.22-16-generic_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.22-16-rt_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.22-16-server_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.22-16-ume_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.22-16-virtual_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.22-16-xen_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.22-16-386_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.22-16-generic_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.22-16-server_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.22-16-virtual_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.22-16-386_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.22-16-generic_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.22-16-server_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.22-16-virtual_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-ubuntu-modules", ver:"2.6.22-16-386_2.6.22-16.41", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-ubuntu-modules", ver:"2.6.22-16-generic_2.6.22-16.41", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-ubuntu-modules", ver:"2.6.22-16-server_2.6.22-16.41", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-ubuntu-modules", ver:"2.6.22-16-virtual_2.6.22-16.41", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"avm-fritz-kernel-source", ver:"3.11+2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fglrx-kernel-source", ver:"8.37.6+2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.22-16-rt_2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.22-16-xen_2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-legacy-dev", ver:"1.0.7185+2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-legacy", ver:"1.0.7185+2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-kernel-source", ver:"1.0.9639+2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-legacy-kernel-source", ver:"1.0.7185+2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"avm-fritz-firmware", ver:"2.6.22-16_3.11+2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fglrx-control", ver:"8.37.6+2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.22-16-386_2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.22-16-generic_2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-dev", ver:"1.0.9639+2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-new-dev", ver:"100.14.19+2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-new", ver:"100.14.19+2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx", ver:"1.0.9639+2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-new-kernel-source", ver:"100.14.19+2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xorg-driver-fglrx-dev", ver:"7.1.0-8.37.6+2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xorg-driver-fglrx", ver:"7.1.0-8.37.6+2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.22-16-rt_2.6.22-16.17", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.22-16-ume_2.6.22-16.17", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-backports-modules", ver:"2.6.22-16-xen_2.6.22-16.17", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.22-16-rt_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.22-16-ume_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.22-16-xen_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-ubuntu-modules", ver:"2.6.22-16-rt_2.6.22-16.41", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-ubuntu-modules", ver:"2.6.22-16-ume_2.6.22-16.41", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-ubuntu-modules", ver:"2.6.22-16-xen_2.6.22-16.41", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-doc", ver:"2.6.22_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.22-16_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-kernel-devel", ver:"2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-source", ver:"2.6.22_2.6.22-16.60", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules-common", ver:"2.6.22.4-16.12", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
