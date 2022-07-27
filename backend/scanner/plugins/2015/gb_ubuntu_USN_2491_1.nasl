###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-ec2 USN-2491-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.842083");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-02-04 06:11:08 +0100 (Wed, 04 Feb 2015)");
  script_cve_id("CVE-2014-9322", "CVE-2014-3611", "CVE-2014-3610", "CVE-2014-8133",
  "CVE-2014-9420");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for linux-ec2 USN-2491-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ec2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Andy Lutomirski discovered that the Linux
kernel does not properly handle faults associated with the Stack Segment (SS)
register in the x86 architecture. A local attacker could exploit this flaw to gain
administrative privileges. (CVE-2014-9322)

Lars Bull reported a race condition in the PIT (programmable interrupt
timer) emulation in the KVM (Kernel Virtual Machine) subsystem of the Linux
kernel. A local guest user with access to PIT i/o ports could exploit this
flaw to cause a denial of service (crash) on the host. (CVE-2014-3611)

Lars Bull and Nadav Amit reported a flaw in how KVM (the Kernel Virtual
Machine) handles noncanonical writes to certain MSR registers. A privileged
guest user can exploit this flaw to cause a denial of service (kernel
panic) on the host. (CVE-2014-3610)

Andy Lutomirski discovered an information leak in the Linux kernel's Thread
Local Storage (TLS) implementation allowing users to bypass the espfix to
obtain information that could be used to bypass the Address Space Layout
Randomization (ASLR) protection mechanism. A local user could exploit this
flaw to obtain potentially sensitive information from kernel memory.
(CVE-2014-8133)

Prasad J Pandit reported a flaw in the rock_continue function of the Linux
kernel's ISO 9660 CDROM file system. A local user could exploit this flaw
to cause a denial of service (system crash or hang). (CVE-2014-9420)");
  script_tag(name:"affected", value:"linux-ec2 on Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2491-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04 LTS");

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

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-375-ec2", ver:"2.6.32-375.92", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
