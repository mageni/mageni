###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_2342_1.nasl 14140 2019-03-13 12:26:09Z cfischer $
#
# Ubuntu Update for qemu USN-2342-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.841962");
  script_version("$Revision: 14140 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-09-09 05:55:17 +0200 (Tue, 09 Sep 2014)");
  script_cve_id("CVE-2013-4148", "CVE-2013-4149", "CVE-2013-4150", "CVE-2013-4151",
                "CVE-2013-4526", "CVE-2013-4527", "CVE-2013-4529", "CVE-2013-4530",
                "CVE-2013-4531", "CVE-2013-4532", "CVE-2013-4533", "CVE-2013-4534",
                "CVE-2013-4535", "CVE-2013-4536", "CVE-2013-4537", "CVE-2013-4538",
                "CVE-2013-4539", "CVE-2013-4540", "CVE-2013-4541", "CVE-2013-4542",
                "CVE-2013-6399", "CVE-2014-0182", "CVE-2014-3461", "CVE-2014-0142",
                "CVE-2014-0143", "CVE-2014-0144", "CVE-2014-0145", "CVE-2014-0146",
                "CVE-2014-0147", "CVE-2014-0222", "CVE-2014-0223", "CVE-2014-3471");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ubuntu Update for qemu USN-2342-1");
  script_tag(name:"insight", value:"Michael S. Tsirkin, Anthony Liguori, and Michael Roth discovered multiple
issues with QEMU state loading after migration. An attacker able to modify
the state data could use these issues to cause a denial of service, or
possibly execute arbitrary code. (CVE-2013-4148, CVE-2013-4149,
CVE-2013-4150, CVE-2013-4151, CVE-2013-4526, CVE-2013-4527, CVE-2013-4529,
CVE-2013-4530, CVE-2013-4531, CVE-2013-4532, CVE-2013-4533, CVE-2013-4534,
CVE-2013-4535, CVE-2013-4536, CVE-2013-4537, CVE-2013-4538, CVE-2013-4539,
CVE-2013-4540, CVE-2013-4541, CVE-2013-4542, CVE-2013-6399, CVE-2014-0182,
CVE-2014-3461)

Kevin Wolf, Stefan Hajnoczi, Fam Zheng, Jeff Cody, Stefan Hajnoczi, and
others discovered multiple issues in the QEMU block drivers. An attacker
able to modify disk images could use these issues to cause a denial of
service, or possibly execute arbitrary code. (CVE-2014-0142, CVE-2014-0143,
CVE-2014-0144, CVE-2014-0145, CVE-2014-0146, CVE-2014-0147, CVE-2014-0222,
CVE-2014-0223)

It was discovered that QEMU incorrectly handled certain PCIe bus hotplug
operations. A malicious guest could use this issue to crash the QEMU host,
resulting in a denial of service. (CVE-2014-3471)");
  script_tag(name:"affected", value:"qemu on Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2342-1/");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04 LTS|12\.04 LTS|10\.04 LTS)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"qemu-system", ver:"2.0.0+dfsg-2ubuntu1.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-aarch64", ver:"2.0.0+dfsg-2ubuntu1.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-arm", ver:"2.0.0+dfsg-2ubuntu1.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-mips", ver:"2.0.0+dfsg-2ubuntu1.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-misc", ver:"2.0.0+dfsg-2ubuntu1.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"2.0.0+dfsg-2ubuntu1.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"2.0.0+dfsg-2ubuntu1.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"qemu-system-x86", ver:"2.0.0+dfsg-2ubuntu1.3", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"qemu-kvm", ver:"1.0+noroms-0ubuntu14.17", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"qemu-kvm", ver:"0.12.3+noroms-0ubuntu9.24", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
