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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5703.1");
  script_cve_id("CVE-2022-1882", "CVE-2022-26373", "CVE-2022-3176", "CVE-2022-36879", "CVE-2022-39189");
  script_tag(name:"creation_date", value:"2022-10-27 04:28:34 +0000 (Thu, 27 Oct 2022)");
  script_version("2022-10-27T10:11:07+0000");
  script_tag(name:"last_modification", value:"2022-10-27 10:11:07 +0000 (Thu, 27 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-08 18:37:00 +0000 (Thu, 08 Sep 2022)");

  script_name("Ubuntu: Security Advisory (USN-5703-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5703-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5703-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-intel-iotg' package(s) announced via the USN-5703-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Selim Enes Karaduman discovered that a race condition existed in the
General notification queue implementation of the Linux kernel, leading to a
use-after-free vulnerability. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2022-1882)

Pawan Kumar Gupta, Alyssa Milburn, Amit Peled, Shani Rehana, Nir Shildan
and Ariel Sabba discovered that some Intel processors with Enhanced
Indirect Branch Restricted Speculation (eIBRS) did not properly handle RET
instructions after a VM exits. A local attacker could potentially use this
to expose sensitive information. (CVE-2022-26373)

Eric Biggers discovered that a use-after-free vulnerability existed in the
io_uring subsystem in the Linux kernel. A local attacker could possibly use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2022-3176)

It was discovered that the Netlink Transformation (XFRM) subsystem in the
Linux kernel contained a reference counting error. A local attacker could
use this to cause a denial of service (system crash). (CVE-2022-36879)

Jann Horn discovered that the KVM subsystem in the Linux kernel did not
properly handle TLB flush operations in some situations. A local attacker
in a guest VM could use this to cause a denial of service (guest crash) or
possibly execute arbitrary code in the guest kernel. (CVE-2022-39189)");

  script_tag(name:"affected", value:"'linux-intel-iotg' package(s) on Ubuntu 22.04.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1017-intel-iotg", ver:"5.15.0-1017.22", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel-iotg", ver:"5.15.0.1017.18", rls:"UBUNTU22.04 LTS"))) {
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
