###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3871_1.nasl 14288 2019-03-18 16:34:17Z cfischer $
#
# Ubuntu Update for linux USN-3871-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.843884");
  script_version("$Revision: 14288 $");
  script_cve_id("CVE-2018-10876", "CVE-2018-10879", "CVE-2018-10877", "CVE-2018-10878",
                "CVE-2018-10882", "CVE-2018-10880", "CVE-2018-10883", "CVE-2018-14625",
                "CVE-2018-16882", "CVE-2018-17972", "CVE-2018-18281", "CVE-2018-19407",
                "CVE-2018-9516");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-01-30 04:02:08 +0100 (Wed, 30 Jan 2019)");
  script_name("Ubuntu Update for linux USN-3871-1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04 LTS");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3871-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the USN-3871-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Wen Xu discovered that a use-after-free
vulnerability existed in the ext4 filesystem implementation in the Linux kernel.
An attacker could use this to construct a malicious ext4 image that, when mounted,
could cause a denial of service (system crash) or possibly execute arbitrary code.
(CVE-2018-10876, CVE-2018-10879)

Wen Xu discovered that a buffer overflow existed in the ext4 filesystem
implementation in the Linux kernel. An attacker could use this to construct
a malicious ext4 image that, when mounted, could cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2018-10877)

Wen Xu discovered that an out-of-bounds write vulnerability existed in the
ext4 filesystem implementation in the Linux kernel. An attacker could use
this to construct a malicious ext4 image that, when mounted, could cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2018-10878, CVE-2018-10882)

Wen Xu discovered that the ext4 filesystem implementation in the Linux
kernel did not properly ensure that xattr information remained in inode
bodies. An attacker could use this to construct a malicious ext4 image
that, when mounted, could cause a denial of service (system crash).
(CVE-2018-10880)

Wen Xu discovered that the ext4 file system implementation in the Linux
kernel could possibly perform an out of bounds write when updating the
journal for an inline file. An attacker could use this to construct a
malicious ext4 image that, when mounted, could cause a denial of service
(system crash). (CVE-2018-10883)

It was discovered that a race condition existed in the vsock address family
implementation of the Linux kernel that could lead to a use-after-free
condition. A local attacker in a guest virtual machine could use this to
expose sensitive information (host machine kernel memory). (CVE-2018-14625)

Cfir Cohen discovered that a use-after-free vulnerability existed in the
KVM implementation of the Linux kernel, when handling interrupts in
environments where nested virtualization is in use (nested KVM
virtualization is not enabled by default in Ubuntu kernels). A local
attacker in a guest VM could possibly use this to gain administrative
privileges in a host machine. (CVE-2018-16882)

Jann Horn discovered that the procfs file system implementation in the
Linux kernel did not properly restrict the ability to inspect the kernel
stack of an arbitrary task. A local attacker could use this to expose
sensitive information. (CVE-2018-17972)

Jann Horn discovered that the mremap() system call in the Linux kernel did
not properly flush the TLB when completing, potentially lea ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"linux on Ubuntu 18.04 LTS.");

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

if(release == "UBUNTU18.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-4.15.0-44-generic", ver:"4.15.0-44.47", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.15.0-44-generic-lpae", ver:"4.15.0-44.47", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.15.0-44-lowlatency", ver:"4.15.0-44.47", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.15.0-44-snapdragon", ver:"4.15.0-44.47", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.15.0.44.46", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.15.0.44.46", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.15.0.44.46", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-snapdragon", ver:"4.15.0.44.46", rls:"UBUNTU18.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
