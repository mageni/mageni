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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2011.1074.2");
  script_cve_id("CVE-2009-4895", "CVE-2010-2066", "CVE-2010-2226", "CVE-2010-2248", "CVE-2010-2478", "CVE-2010-2495", "CVE-2010-2521", "CVE-2010-2524", "CVE-2010-2538", "CVE-2010-2798", "CVE-2010-2942", "CVE-2010-2943", "CVE-2010-2946", "CVE-2010-2954", "CVE-2010-2955", "CVE-2010-2962", "CVE-2010-2963", "CVE-2010-3015", "CVE-2010-3067", "CVE-2010-3078", "CVE-2010-3079", "CVE-2010-3080", "CVE-2010-3081", "CVE-2010-3084", "CVE-2010-3296", "CVE-2010-3297", "CVE-2010-3298", "CVE-2010-3301", "CVE-2010-3310", "CVE-2010-3432", "CVE-2010-3437", "CVE-2010-3442", "CVE-2010-3448", "CVE-2010-3477", "CVE-2010-3698", "CVE-2010-3705", "CVE-2010-3848", "CVE-2010-3849", "CVE-2010-3850", "CVE-2010-3858", "CVE-2010-3861", "CVE-2010-3904", "CVE-2010-4072", "CVE-2010-4073", "CVE-2010-4074", "CVE-2010-4078", "CVE-2010-4079", "CVE-2010-4165", "CVE-2010-4169", "CVE-2010-4249");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-10 16:09:00 +0000 (Mon, 10 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-1074-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1074-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1074-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-fsl-imx51' package(s) announced via the USN-1074-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered that the RDS network protocol did not correctly
check certain parameters. A local attacker could exploit this gain root
privileges. (CVE-2010-3904)

Nelson Elhage discovered several problems with the Acorn Econet protocol
driver. A local user could cause a denial of service via a NULL pointer
dereference, escalate privileges by overflowing the kernel stack, and
assign Econet addresses to arbitrary interfaces. (CVE-2010-3848,
CVE-2010-3849, CVE-2010-3850)

Ben Hawkes discovered that the Linux kernel did not correctly filter
registers on 64bit kernels when performing 32bit system calls. On a 64bit
system, a local attacker could manipulate 32bit system calls to gain root
privileges. (CVE-2010-3301)

Ben Hawkes discovered that the Linux kernel did not correctly validate
memory ranges on 64bit kernels when allocating memory on behalf of 32bit
system calls. On a 64bit system, a local attacker could perform malicious
multicast getsockopt calls to gain root privileges. (CVE-2010-3081)

Al Viro discovered a race condition in the TTY driver. A local attacker
could exploit this to crash the system, leading to a denial of service.
(CVE-2009-4895)

Dan Rosenberg discovered that the MOVE_EXT ext4 ioctl did not correctly
check file permissions. A local attacker could overwrite append-only files,
leading to potential data loss. (CVE-2010-2066)

Dan Rosenberg discovered that the swapexit xfs ioctl did not correctly
check file permissions. A local attacker could exploit this to read from
write-only files, leading to a loss of privacy. (CVE-2010-2226)

Suresh Jayaraman discovered that CIFS did not correctly validate certain
response packets. A remote attacker could send specially crafted traffic
that would crash the system, leading to a denial of service.
(CVE-2010-2248)

Ben Hutchings discovered that the ethtool interface did not correctly check
certain sizes. A local attacker could perform malicious ioctl calls that
could crash the system, leading to a denial of service. (CVE-2010-2478,
CVE-2010-3084)

James Chapman discovered that L2TP did not correctly evaluate checksum
capabilities. If an attacker could make malicious routing changes, they
could crash the system, leading to a denial of service. (CVE-2010-2495)

Neil Brown discovered that NFSv4 did not correctly check certain write
requests. A remote attacker could send specially crafted traffic that could
crash the system or possibly gain root privileges. (CVE-2010-2521)

David Howells discovered that DNS resolution in CIFS could be spoofed. A
local attacker could exploit this to control DNS replies, leading to a loss
of privacy and possible privilege escalation. (CVE-2010-2524)

Dan Rosenberg discovered that the btrfs filesystem did not correctly
validate permissions when using the clone function. A local attacker could
overwrite the contents of file handles that were opened for append-only, or
potentially ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-fsl-imx51' package(s) on Ubuntu 10.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-608-imx51", ver:"2.6.31-608.22", rls:"UBUNTU10.04 LTS"))) {
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
