###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_543_1.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for linux-restricted-modules-2.6.17/20, vmware-player-kernel-2.6.15 vulnerabilities USN-543-1
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
tag_insight = "Neel Mehta and Ryan Smith discovered that the VMWare Player DHCP server
  did not correctly handle certain packet structures.  Remote attackers
  could send specially crafted packets and gain root privileges.
  (CVE-2007-0061, CVE-2007-0062, CVE-2007-0063)

  Rafal Wojtczvk discovered multiple memory corruption issues in VMWare
  Player.  Attackers with administrative privileges in a guest operating
  system could cause a denial of service or possibly execute arbitrary
  code on the host operating system.  (CVE-2007-4496, CVE-2007-4497)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-543-1";
tag_affected = "linux-restricted-modules-2.6.17/20, vmware-player-kernel-2.6.15 vulnerabilities on Ubuntu 6.06 LTS ,
  Ubuntu 6.10 ,
  Ubuntu 7.04";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-543-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.308339");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-0061", "CVE-2007-0062", "CVE-2007-0063", "CVE-2007-4496", "CVE-2007-4497");
  script_name( "Ubuntu Update for linux-restricted-modules-2.6.17/20, vmware-player-kernel-2.6.15 vulnerabilities USN-543-1");

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

if(release == "UBUNTU7.04")
{

  if ((res = isdpkgvuln(pkg:"avm-fritz-kernel-source", ver:"3.11+2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fglrx-kernel-source", ver:"8.34.8+2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.20-16-lowlatency_2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-legacy-dev", ver:"1.0.7184+2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-legacy", ver:"1.0.7184+2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-kernel-source", ver:"1.0.9631+2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-legacy-kernel-source", ver:"1.0.7184+2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"avm-fritz-firmware", ver:"2.6.20-16_3.11+2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fglrx-control", ver:"8.34.8+2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.20-16-386_2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.20-16-generic_2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-dev", ver:"1.0.9631+2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-new-dev", ver:"1.0.9755+2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-new", ver:"1.0.9755+2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx", ver:"1.0.9631+2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-new-kernel-source", ver:"1.0.9755+2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"vmware-player-kernel-modules", ver:"2.6.20-16_2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"vmware-server-kernel-modules", ver:"2.6.20-16_2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"vmware-tools-kernel-modules", ver:"2.6.20-16_2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xorg-driver-fglrx-dev", ver:"7.1.0-8.34.8+2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xorg-driver-fglrx", ver:"7.1.0-8.34.8+2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules-common", ver:"2.6.20.6-16.30", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"vmware-player-kernel-modules", ver:"2.6.15-29_2.6.15.11-13", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"vmware-player-kernel-modules", ver:"2.6.15.11-13", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"vmware-player-kernel-source", ver:"2.6.15.11-13", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.10")
{

  if ((res = isdpkgvuln(pkg:"avm-fritz-kernel-source", ver:"3.11+2.6.17.9-12.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fglrx-kernel-source", ver:"8.28.8+2.6.17.9-12.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-legacy-dev", ver:"1.0.7184+2.6.17.9-12.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-legacy", ver:"1.0.7184+2.6.17.9-12.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-kernel-source", ver:"1.0.8776+2.6.17.9-12.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-legacy-kernel-source", ver:"1.0.7184+2.6.17.9-12.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"avm-fritz-firmware", ver:"2.6.17-12_3.11+2.6.17.9-12.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"fglrx-control", ver:"8.28.8+2.6.17.9-12.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.17-12-386_2.6.17.9-12.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules", ver:"2.6.17-12-generic_2.6.17.9-12.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx-dev", ver:"1.0.8776+2.6.17.9-12.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"nvidia-glx", ver:"1.0.8776+2.6.17.9-12.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"vmware-player-kernel-modules", ver:"2.6.17-12_2.6.17.9-12.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xorg-driver-fglrx-dev", ver:"7.1.0-8.28.8+2.6.17.9-12.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xorg-driver-fglrx", ver:"7.1.0-8.28.8+2.6.17.9-12.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-restricted-modules-common", ver:"2.6.17.9-12.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
