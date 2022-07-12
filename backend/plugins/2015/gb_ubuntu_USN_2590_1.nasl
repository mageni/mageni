###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux USN-2590-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842185");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-05-01 05:50:13 +0200 (Fri, 01 May 2015)");
  script_cve_id("CVE-2015-2150", "CVE-2015-2666", "CVE-2015-2830", "CVE-2015-2922");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux USN-2590-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Jan Beulich discovered the Xen virtual
machine subsystem of the Linux kernel did not properly restrict access to PCI
command registers. A local guest user could exploit this flaw to cause a denial
of service (host crash). (CVE-2015-2150)

A stack overflow was discovered in the the microcode loader for the intel
x86 platform. A local attacker could exploit this flaw to cause a denial of
service (kernel crash) or to potentially execute code with kernel
privileges. (CVE-2015-2666)

A privilege escalation was discovered in the fork syscal vi the int80 entry
on 64 bit kernels with 32 bit emulation support. An unprivileged local
attacker could exploit this flaw to increase their privileges on the
system. (CVE-2015-2830)

It was discovered that the Linux kernel's IPv6 networking stack has a flaw
that allows using route advertisement (RA) messages to set the 'hop_limit'
to values that are too low. An unprivileged attacker on a local network
could exploit this flaw to cause a denial of service (IPv6 messages
dropped). (CVE-2015-2922)");
  script_tag(name:"affected", value:"linux on Ubuntu 14.10");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2590-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.10");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.10")
{

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-36-generic", ver:"3.16.0-36.48", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-36-generic-lpae", ver:"3.16.0-36.48", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-36-lowlatency", ver:"3.16.0-36.48", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-36-powerpc-e500mc", ver:"3.16.0-36.48", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-36-powerpc-smp", ver:"3.16.0-36.48", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-36-powerpc64-emb", ver:"3.16.0-36.48", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-36-powerpc64-smp", ver:"3.16.0-36.48", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
