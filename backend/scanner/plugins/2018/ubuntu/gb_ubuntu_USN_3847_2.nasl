###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3847_2.nasl 14288 2019-03-18 16:34:17Z cfischer $
#
# Ubuntu Update for linux-aws-hwe USN-3847-2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.843860");
  script_version("$Revision: 14288 $");
  script_cve_id("CVE-2018-10902", "CVE-2018-12896", "CVE-2018-14734",
                "CVE-2018-16276", "CVE-2018-18445", "CVE-2018-18690", "CVE-2018-18710");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-12-21 07:24:09 +0100 (Fri, 21 Dec 2018)");
  script_name("Ubuntu Update for linux-aws-hwe USN-3847-2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04 LTS");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3847-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws-hwe'
  package(s) announced via the USN-3847-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3847-1 fixed vulnerabilities in the Linux kernel for Ubuntu 18.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 18.04 LTS for Ubuntu
16.04 LTS.

It was discovered that a race condition existed in the raw MIDI driver for
the Linux kernel, leading to a double free vulnerability. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2018-10902)

It was discovered that an integer overrun vulnerability existed in the
POSIX timers implementation in the Linux kernel. A local attacker could use
this to cause a denial of service. (CVE-2018-12896)

Noam Rathaus discovered that a use-after-free vulnerability existed in the
Infiniband implementation in the Linux kernel. An attacker could use this
to cause a denial of service (system crash). (CVE-2018-14734)

It was discovered that the YUREX USB device driver for the Linux kernel did
not properly restrict user space reads or writes. A physically proximate
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2018-16276)

It was discovered that the BPF verifier in the Linux kernel did not
correctly compute numeric bounds in some situations. A local attacker could
use this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2018-18445)

Kanda Motohiro discovered that writing extended attributes to an XFS file
system in the Linux kernel in certain situations could cause an error
condition to occur. A local attacker could use this to cause a denial of
service. (CVE-2018-18690)

It was discovered that an integer overflow vulnerability existed in the
CDROM driver of the Linux kernel. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2018-18710)");

  script_tag(name:"affected", value:"linux-aws-hwe on Ubuntu 16.04 LTS.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-4.15.0-1026-gcp", ver:"4.15.0-1026.27~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.15.0-1031-aws", ver:"4.15.0-1031.33~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.15.0-1036-azure", ver:"4.15.0-1036.38~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.15.0-43-generic", ver:"4.15.0-43.46~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.15.0-43-generic-lpae", ver:"4.15.0-43.46~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.15.0-43-lowlatency", ver:"4.15.0-43.46~16.04.1", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-aws-hwe", ver:"4.15.0.1031.32", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1036.41", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-gcp", ver:"4.15.0.1026.40", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic-hwe-16.04", ver:"4.15.0.43.64", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-16.04", ver:"4.15.0.43.64", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-gke", ver:"4.15.0.1026.40", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-16.04", ver:"4.15.0.43.64", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
