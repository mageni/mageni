###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_3696_2.nasl 14288 2019-03-18 16:34:17Z cfischer $
#
# Ubuntu Update for linux-aws USN-3696-2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.843578");
  script_version("$Revision: 14288 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 17:34:17 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-07-03 05:48:45 +0200 (Tue, 03 Jul 2018)");
  script_cve_id("CVE-2017-18255", "CVE-2017-18257", "CVE-2018-1000204", "CVE-2018-10087",
                "CVE-2018-10124", "CVE-2018-3665", "CVE-2018-5814", "CVE-2018-7755",
                "CVE-2017-13695", "CVE-2018-10021");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux-aws USN-3696-2");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"USN-3696-1 fixed vulnerabilities in the Linux kernel for
Ubuntu 16.04 LTS. This update provides the corresponding updates for the Linux Hardware Enablement
(HWE) kernel from Ubuntu 16.04 LTS for Ubuntu 14.04 LTS.

It was discovered that an integer overflow existed in the perf subsystem of
the Linux kernel. A local attacker could use this to cause a denial of
service (system crash). (CVE-2017-18255)

Wei Fang discovered an integer overflow in the F2FS filesystem
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service. (CVE-2017-18257)

It was discovered that an information leak existed in the generic SCSI
driver in the Linux kernel. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2018-1000204)

It was discovered that the wait4() system call in the Linux kernel did not
properly validate its arguments in some situations. A local attacker could
possibly use this to cause a denial of service. (CVE-2018-10087)

It was discovered that the kill() system call implementation in the Linux
kernel did not properly validate its arguments in some situations. A local
attacker could possibly use this to cause a denial of service.
(CVE-2018-10124)

Julian Stecklina and Thomas Prescher discovered that FPU register states
(such as MMX, SSE, and AVX registers) which are lazily restored are
potentially vulnerable to a side channel attack. A local attacker could use
this to expose sensitive information. (CVE-2018-3665)

Jakub Jirasek discovered that multiple use-after-errors existed in the
USB/IP implementation in the Linux kernel. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2018-5814)

It was discovered that an information leak vulnerability existed in the
floppy driver in the Linux kernel. A local attacker could use this to
expose sensitive information (kernel memory). (CVE-2018-7755)

Seunghun Han discovered an information leak in the ACPI handling code in
the Linux kernel when handling early termination of ACPI table loading. A
local attacker could use this to expose sensitive informal (kernel address
locations). (CVE-2017-13695)

It was discovered that a memory leak existed in the Serial Attached SCSI
(SAS) implementation in the Linux kernel. A physically proximate attacker
could use this to cause a denial of service (memory exhaustion).
(CVE-2018-10021)");
  script_tag(name:"affected", value:"linux-aws on Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3696-2/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04 LTS");

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

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-1024-aws", ver:"4.4.0-1024.25", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-130-generic", ver:"4.4.0-130.156~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-130-generic-lpae", ver:"4.4.0-130.156~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-130-lowlatency", ver:"4.4.0-130.156~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-130-powerpc-e500mc", ver:"4.4.0-130.156~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-130-powerpc-smp", ver:"4.4.0-130.156~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-130-powerpc64-emb", ver:"4.4.0-130.156~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-130-powerpc64-smp", ver:"4.4.0-130.156~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1024.24", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic-lpae-lts-xenial", ver:"4.4.0.130.110", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.130.110", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.130.110", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc-lts-xenial", ver:"4.4.0.130.110", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc-smp-lts-xenial", ver:"4.4.0.130.110", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc64-emb-lts-xenial", ver:"4.4.0.130.110", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc64-smp-lts-xenial", ver:"4.4.0.130.110", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
