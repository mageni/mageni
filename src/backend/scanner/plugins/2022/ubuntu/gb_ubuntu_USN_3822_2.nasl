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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2018.3822.2");
  script_cve_id("CVE-2016-9588", "CVE-2017-13168", "CVE-2017-16649", "CVE-2018-16658", "CVE-2018-9363");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-3822-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3822-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3822-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-trusty' package(s) announced via the USN-3822-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3822-1 fixed vulnerabilities in the Linux kernel for Ubuntu 14.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 14.04 LTS for Ubuntu
12.04 ESM.

Jim Mattson discovered that the KVM implementation in the Linux kernel
mismanages the #BP and #OF exceptions. A local attacker in a guest virtual
machine could use this to cause a denial of service (guest OS crash).
(CVE-2016-9588)

It was discovered that the generic SCSI driver in the Linux kernel did not
properly enforce permissions on kernel memory access. A local attacker
could use this to expose sensitive information or possibly elevate
privileges. (CVE-2017-13168)

Andrey Konovalov discovered that the CDC USB Ethernet driver did not
properly validate device descriptors. A physically proximate attacker could
use this to cause a denial of service (system crash). (CVE-2017-16649)

It was discovered that an integer overflow existed in the CD-ROM driver of
the Linux kernel. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2018-16658)

It was discovered that an integer overflow existed in the HID Bluetooth
implementation in the Linux kernel that could lead to a buffer overwrite.
An attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2018-9363)");

  script_tag(name:"affected", value:"'linux-lts-trusty' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-162-generic-lpae", ver:"3.13.0-162.212~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-162-generic", ver:"3.13.0-162.212~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-lts-trusty", ver:"3.13.0.162.152", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-trusty", ver:"3.13.0.162.152", rls:"UBUNTU12.04 LTS"))) {
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
