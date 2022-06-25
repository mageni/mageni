###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_509_1.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for linux-source-2.6.17 vulnerabilities USN-509-1
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
tag_insight = "A flaw in the sysfs_readdir function allowed a local user to cause a
  denial of service by dereferencing a NULL pointer. (CVE-2007-3104)

  A buffer overflow was discovered in the random number generator.  In
  environments with granular assignment of root privileges, a local attacker
  could gain additional privileges. (CVE-2007-3105)
  
  A flaw was discovered in the usblcd driver.  A local attacker could cause
  large amounts of kernel memory consumption, leading to a denial of service.
  (CVE-2007-3513)
  
  It was discovered that certain setuid-root processes did not correctly
  reset process death signal handlers.  A local user could manipulate this
  to send signals to processes they would not normally have access to.
  (CVE-2007-3848)
  
  The Direct Rendering Manager for the i915 driver could be made to write
  to arbitrary memory locations.  An attacker with access to a running X11
  session could send a specially crafted buffer and gain root privileges.
  (CVE-2007-3851)
  
  It was discovered that the aacraid SCSI driver did not correctly check
  permissions on certain ioctls.  A local attacker could cause a denial
  of service or gain privileges. (CVE-2007-4308)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-509-1";
tag_affected = "linux-source-2.6.17 vulnerabilities on Ubuntu 6.10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-509-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.305751");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2007-3104", "CVE-2007-3105", "CVE-2007-3513", "CVE-2007-3848", "CVE-2007-3851", "CVE-2007-4308");
  script_name( "Ubuntu Update for linux-source-2.6.17 vulnerabilities USN-509-1");

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

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.17-12-386_2.6.17.1-12.40", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.17-12-generic_2.6.17.1-12.40", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.17-12-server-bigiron_2.6.17.1-12.40", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.17-12-server_2.6.17.1-12.40", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-headers", ver:"2.6.17-12_2.6.17.1-12.40", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.17-12-386_2.6.17.1-12.40", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.17-12-generic_2.6.17.1-12.40", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.17-12-server-bigiron_2.6.17.1-12.40", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image", ver:"2.6.17-12-server_2.6.17.1-12.40", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.17-12-386_2.6.17.1-12.40", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.17-12-generic_2.6.17.1-12.40", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.17-12-server-bigiron_2.6.17.1-12.40", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-debug", ver:"2.6.17-12-server_2.6.17.1-12.40", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.17.1-12.40", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-kdump", ver:"2.6.17.1-12.40", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-doc", ver:"2.6.17_2.6.17.1-12.40", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-kernel-devel", ver:"2.6.17.1-12.40", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-source", ver:"2.6.17_2.6.17.1-12.40", rls:"UBUNTU6.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
