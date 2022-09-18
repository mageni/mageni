# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2011.1093.1");
  script_cve_id("CVE-2010-2478", "CVE-2010-2942", "CVE-2010-2943", "CVE-2010-2954", "CVE-2010-2955", "CVE-2010-2960", "CVE-2010-2962", "CVE-2010-2963", "CVE-2010-3067", "CVE-2010-3078", "CVE-2010-3079", "CVE-2010-3080", "CVE-2010-3084", "CVE-2010-3296", "CVE-2010-3297", "CVE-2010-3298", "CVE-2010-3310", "CVE-2010-3432", "CVE-2010-3437", "CVE-2010-3442", "CVE-2010-3448", "CVE-2010-3477", "CVE-2010-3698", "CVE-2010-3705", "CVE-2010-3848", "CVE-2010-3849", "CVE-2010-3850", "CVE-2010-3858", "CVE-2010-3859", "CVE-2010-3861", "CVE-2010-3865", "CVE-2010-3873", "CVE-2010-3874", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-3881", "CVE-2010-3904", "CVE-2010-4072", "CVE-2010-4073", "CVE-2010-4075", "CVE-2010-4079", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4082", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4158", "CVE-2010-4160", "CVE-2010-4162", "CVE-2010-4163", "CVE-2010-4164", "CVE-2010-4165", "CVE-2010-4169", "CVE-2010-4175", "CVE-2010-4242", "CVE-2010-4248", "CVE-2010-4249", "CVE-2010-4258", "CVE-2010-4343", "CVE-2010-4346", "CVE-2010-4526", "CVE-2010-4527", "CVE-2010-4648", "CVE-2010-4649", "CVE-2010-4650", "CVE-2010-4655", "CVE-2010-4656", "CVE-2010-4668", "CVE-2011-0006", "CVE-2011-0521", "CVE-2011-0712", "CVE-2011-1010", "CVE-2011-1012", "CVE-2011-1044", "CVE-2011-1082", "CVE-2011-1093");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-10 16:09:00 +0000 (Mon, 10 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-1093-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1093-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1093-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-mvl-dove' package(s) announced via the USN-1093-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered that the RDS network protocol did not correctly
check certain parameters. A local attacker could exploit this gain root
privileges. (CVE-2010-3904)

Nelson Elhage discovered several problems with the Acorn Econet protocol
driver. A local user could cause a denial of service via a NULL pointer
dereference, escalate privileges by overflowing the kernel stack, and
assign Econet addresses to arbitrary interfaces. (CVE-2010-3848,
CVE-2010-3849, CVE-2010-3850)

Ben Hutchings discovered that the ethtool interface did not correctly check
certain sizes. A local attacker could perform malicious ioctl calls that
could crash the system, leading to a denial of service. (CVE-2010-2478,
CVE-2010-3084)

Eric Dumazet discovered that many network functions could leak kernel stack
contents. A local attacker could exploit this to read portions of kernel
memory, leading to a loss of privacy. (CVE-2010-2942, CVE-2010-3477)

Dave Chinner discovered that the XFS filesystem did not correctly order
inode lookups when exported by NFS. A remote attacker could exploit this to
read or write disk blocks that had changed file assignment or had become
unlinked, leading to a loss of privacy. (CVE-2010-2943)

Tavis Ormandy discovered that the IRDA subsystem did not correctly shut
down. A local attacker could exploit this to cause the system to crash or
possibly gain root privileges. (CVE-2010-2954)

Brad Spengler discovered that the wireless extensions did not correctly
validate certain request sizes. A local attacker could exploit this to read
portions of kernel memory, leading to a loss of privacy. (CVE-2010-2955)

Tavis Ormandy discovered that the session keyring did not correctly check
for its parent. On systems without a default session keyring, a local
attacker could exploit this to crash the system, leading to a denial of
service. (CVE-2010-2960)

Kees Cook discovered that the Intel i915 graphics driver did not correctly
validate memory regions. A local attacker with access to the video card
could read and write arbitrary kernel memory to gain root privileges.
(CVE-2010-2962)

Kees Cook discovered that the V4L1 32bit compat interface did not correctly
validate certain parameters. A local attacker on a 64bit system with access
to a video device could exploit this to gain root privileges.
(CVE-2010-2963)

Tavis Ormandy discovered that the AIO subsystem did not correctly validate
certain parameters. A local attacker could exploit this to crash the system
or possibly gain root privileges. (CVE-2010-3067)

Dan Rosenberg discovered that certain XFS ioctls leaked kernel stack
contents. A local attacker could exploit this to read portions of kernel
memory, leading to a loss of privacy. (CVE-2010-3078)

Robert Swiecki discovered that ftrace did not correctly handle mutexes. A
local attacker could exploit this to crash the kernel, leading to a denial
of service. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-mvl-dove' package(s) on Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-216-dove", ver:"2.6.32-216.33", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-416-dove", ver:"2.6.32-416.33", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
