# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.844121");
  script_version("2019-08-08T09:10:13+0000");
  script_cve_id("CVE-2019-11487", "CVE-2019-11599", "CVE-2019-11833", "CVE-2019-11884");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-08-08 09:10:13 +0000 (Thu, 08 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-02 02:00:28 +0000 (Fri, 02 Aug 2019)");
  script_name("Ubuntu Update for linux-hwe USN-4069-2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04 LTS");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-4069-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-hwe'
  package(s) announced via the USN-4069-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4069-1 fixed vulnerabilities in the Linux kernel for Ubuntu 19.04.
This update provides the corresponding updates for the Linux Hardware
Enablement (HWE) kernel from Ubuntu 19.04 for Ubuntu 18.04 LTS.

It was discovered that an integer overflow existed in the Linux kernel when
reference counting pages, leading to potential use-after-free issues. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2019-11487)

Jann Horn discovered that a race condition existed in the Linux kernel when
performing core dumps. A local attacker could use this to cause a denial of
service (system crash) or expose sensitive information. (CVE-2019-11599)

It was discovered that the ext4 file system implementation in the Linux
kernel did not properly zero out memory in some situations. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2019-11833)

It was discovered that the Bluetooth Human Interface Device Protocol (HIDP)
implementation in the Linux kernel did not properly verify strings were
NULL terminated in certain situations. A local attacker could use this to
expose sensitive information (kernel memory). (CVE-2019-11884)");

  script_tag(name:"affected", value:"'linux-hwe' package(s) on Ubuntu 18.04 LTS.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-23-generic", ver:"5.0.0-23.24~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-23-generic-lpae", ver:"5.0.0-23.24~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.0.0-23-lowlatency", ver:"5.0.0-23.24~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-18.04", ver:"5.0.0.23.80", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-18.04", ver:"5.0.0.23.80", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-18.04", ver:"5.0.0.23.80", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon-hwe-18.04", ver:"5.0.0.23.80", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-hwe-18.04", ver:"5.0.0.23.80", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
