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
  script_oid("1.3.6.1.4.1.25623.1.0.845309");
  script_version("2022-04-14T11:53:12+0000");
  script_cve_id("CVE-2022-25636", "CVE-2022-23960", "CVE-2022-23222", "CVE-2022-0847", "CVE-2022-0492", "CVE-2022-0185", "CVE-2022-0001", "CVE-2021-4083", "CVE-2021-4090", "CVE-2021-4155", "CVE-2021-42327", "CVE-2022-0330", "CVE-2022-0435", "CVE-2022-0516", "CVE-2022-0742", "CVE-2022-22942");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-14 11:53:12 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-07 19:43:00 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-02 01:00:26 +0000 (Sat, 02 Apr 2022)");
  script_name("Ubuntu: Security Advisory for linux-intel-5.13 (USN-5362-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04 LTS");

  script_xref(name:"Advisory-ID", value:"USN-5362-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2022-April/006490.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-intel-5.13'
  package(s) announced via the USN-5362-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nick Gregory discovered that the Linux kernel incorrectly handled network
offload functionality. A local attacker could use this to cause a denial of
service or possibly execute arbitrary code. (CVE-2022-25636)

Enrico Barberis, Pietro Frigo, Marius Muench, Herbert Bos, and Cristiano
Giuffrida discovered that hardware mitigations added by ARM to their
processors to address Spectre-BTI were insufficient. A local attacker could
potentially use this to expose sensitive information. (CVE-2022-23960)

It was discovered that the BPF verifier in the Linux kernel did not
properly restrict pointer types in certain situations. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2022-23222)

Max Kellermann discovered that the Linux kernel incorrectly handled Unix
pipes. A local attacker could potentially use this to modify any file that
could be opened for reading. (CVE-2022-0847)

Yiqi Sun and Kevin Wang discovered that the cgroups implementation in the
Linux kernel did not properly restrict access to the cgroups v1
release_agent feature. A local attacker could use this to gain
administrative privileges. (CVE-2022-0492)

William Liu and Jamie Hill-Daniel discovered that the file system context
functionality in the Linux kernel contained an integer underflow
vulnerability, leading to an out-of-bounds write. A local attacker could
use this to cause a denial of service (system crash) or execute arbitrary
code. (CVE-2022-0185)

Enrico Barberis, Pietro Frigo, Marius Muench, Herbert Bos, and Cristiano
Giuffrida discovered that hardware mitigations added by Intel to their
processors to address Spectre-BTI were insufficient. A local attacker could
potentially use this to expose sensitive information. (CVE-2022-0001)

Jann Horn discovered a race condition in the Unix domain socket
implementation in the Linux kernel that could result in a read-after-free.
A local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2021-4083)

It was discovered that the NFS server implementation in the Linux kernel
contained an out-of-bounds write vulnerability. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2021-4090)

Kirill Tkhai discovered that the XFS file system implementation in the
Linux kernel did not calculate size correctly when pre-allocating space in
some situations. A local attacker could use this to expose sensitive
information. (CVE-2021-4155)

It was discovered that the AMD Radeon GPU driver in the Linux kernel  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux-intel-5.13' package(s) on Ubuntu 20.04 LTS.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.13.0-1010-intel", ver:"5.13.0-1010.10", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel", ver:"5.13.0.1010.11", rls:"UBUNTU20.04 LTS"))) {
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