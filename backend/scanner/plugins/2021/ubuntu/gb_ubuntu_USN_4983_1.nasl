# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.844969");
  script_version("2021-06-04T12:02:46+0000");
  script_cve_id("CVE-2021-33200", "CVE-2021-29155", "CVE-2021-31829", "CVE-2021-3501");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-06-07 10:15:34 +0000 (Mon, 07 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-04 03:00:41 +0000 (Fri, 04 Jun 2021)");
  script_name("Ubuntu: Security Advisory for linux-oem-5.10 (USN-4983-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04 LTS");

  script_xref(name:"Advisory-ID", value:"USN-4983-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-June/006061.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oem-5.10'
  package(s) announced via the USN-4983-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Piotr Krysiuk discovered that the eBPF implementation in the Linux kernel
did not properly enforce limits for pointer operations. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2021-33200)

Piotr Krysiuk and Benedict Schlueter discovered that the eBPF
implementation in the Linux kernel performed out of bounds speculation on
pointer arithmetic. A local attacker could use this to expose sensitive
information. (CVE-2021-29155)

Piotr Krysiuk discovered that the eBPF implementation in the Linux kernel
did not properly prevent speculative loads in certain situations. A local
attacker could use this to expose sensitive information (kernel memory).
(CVE-2021-31829)

Reiji Watanabe discovered that the KVM VMX implementation in the Linux
kernel did not properly prevent user space from tampering with an array
index value, leading to a potential out-of-bounds write. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2021-3501)");

  script_tag(name:"affected", value:"'linux-oem-5.10' package(s) on Ubuntu 20.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-1029-oem", ver:"5.10.0-1029.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04", ver:"5.10.0.1029.30", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-20.04b", ver:"5.10.0.1029.30", rls:"UBUNTU20.04 LTS"))) {
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