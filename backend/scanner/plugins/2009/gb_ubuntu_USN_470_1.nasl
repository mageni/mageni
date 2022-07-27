###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_470_1.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for linux-source-2.6.20 vulnerabilities USN-470-1
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
tag_insight = "USN-464-1 fixed several vulnerabilities in the Linux kernel.  Some
  additional code changes were accidentally included in the Feisty update
  which caused trouble for some people who were not using UUID-based
  filesystem mounts.  These changes have been reverted.  We apologize for
  the inconvenience.  For more information see:
  <A HREF='https://launchpad.net/bugs/117314'>https://launchpad.net/bugs/117314</A>
  <A HREF='https://wiki.ubuntu.com/UsingUUID'>https://wiki.ubuntu.com/UsingUUID</A>

  Ilja van Sprundel discovered that Bluetooth setsockopt calls could leak
  kernel memory contents via an uninitialized stack buffer.  A local
  attacker could exploit this flaw to view sensitive kernel information.
  (CVE-2007-1353)
  
  The GEODE-AES driver did not correctly initialize its encryption key.
  Any data encrypted using this type of device would be easily compromised.
  (CVE-2007-2451)
  
  The random number generator was hashing a subset of the available
  entropy, leading to slightly less random numbers.  Additionally, systems
  without an entropy source would be seeded with the same inputs at boot
  time, leading to a repeatable series of random numbers. (CVE-2007-2453)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-470-1";
tag_affected = "linux-source-2.6.20 vulnerabilities on Ubuntu 7.04";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-470-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.307541");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:55:18 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2007-1353", "CVE-2007-2451", "CVE-2007-2453");
  script_name( "Ubuntu Update for linux-source-2.6.20 vulnerabilities USN-470-1");

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

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.20-16-386_2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.20-16-generic_2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.20-16-lowlatency_2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.20-16-server-bigiron_2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.20-16-server_2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.20-16_2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.20-16-386_2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.20-16-generic_2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.20-16-lowlatency_2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.20-16-server-bigiron_2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.20-16-server_2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.20-16-386_2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.20-16-generic_2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.20-16-lowlatency_2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.20-16-server-bigiron_2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.20-16-server_2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-doc", ver:"2.6.20_2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-kernel-devel", ver:"2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-source", ver:"2.6.20_2.6.20-16.29", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
