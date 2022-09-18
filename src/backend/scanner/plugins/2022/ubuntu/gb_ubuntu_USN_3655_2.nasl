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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2018.3655.2");
  script_cve_id("CVE-2017-12134", "CVE-2017-13220", "CVE-2017-13305", "CVE-2017-17449", "CVE-2017-18079", "CVE-2017-18203", "CVE-2017-18204", "CVE-2017-18208", "CVE-2017-18221", "CVE-2018-3639", "CVE-2018-8822");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3655-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3655-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3655-2");
  script_xref(name:"URL", value:"https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/Variant4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-trusty' package(s) announced via the USN-3655-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3655-1 fixed vulnerabilities and added mitigations in the Linux
kernel for Ubuntu 14.04 LTS. This update provides the corresponding
updates for the Linux Hardware Enablement (HWE) kernel from Ubuntu
14.04 LTS for Ubuntu 12.04 ESM.

Jann Horn and Ken Johnson discovered that microprocessors utilizing
speculative execution of a memory read may allow unauthorized memory
reads via a sidechannel attack. This flaw is known as Spectre
Variant 4. A local attacker could use this to expose sensitive
information, including kernel memory. (CVE-2018-3639)

Jan H. Schonherr discovered that the Xen subsystem did not properly handle
block IO merges correctly in some situations. An attacker in a guest vm
could use this to cause a denial of service (host crash) or possibly gain
administrative privileges in the host. (CVE-2017-12134)

It was discovered that the Bluetooth HIP Protocol implementation in the
Linux kernel did not properly validate HID connection setup information. An
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2017-13220)

It was discovered that a buffer overread vulnerability existed in the
keyring subsystem of the Linux kernel. A local attacker could possibly use
this to expose sensitive information (kernel memory). (CVE-2017-13305)

It was discovered that the netlink subsystem in the Linux kernel did not
properly restrict observations of netlink messages to the appropriate net
namespace. A local attacker could use this to expose sensitive information
(kernel netlink traffic). (CVE-2017-17449)

It was discovered that a race condition existed in the i8042 serial device
driver implementation in the Linux kernel. A physically proximate attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2017-18079)

It was discovered that a race condition existed in the Device Mapper
component of the Linux kernel. A local attacker could use this to cause a
denial of service (system crash). (CVE-2017-18203)

It was discovered that a race condition existed in the OCFS2 file system
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (kernel deadlock). (CVE-2017-18204)

It was discovered that an infinite loop could occur in the madvise(2)
implementation in the Linux kernel in certain circumstances. A local
attacker could use this to cause a denial of service (system hang).
(CVE-2017-18208)

Kefeng Wang discovered that a race condition existed in the memory locking
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service. (CVE-2017-18221)

Silvio Cesare discovered a buffer overwrite existed in the NCPFS
implementation in the Linux kernel. A remote attacker controlling a
malicious NCPFS server could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2018-8822)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-149-generic-lpae", ver:"3.13.0-149.199~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-149-generic", ver:"3.13.0-149.199~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-lts-trusty", ver:"3.13.0.149.140", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-trusty", ver:"3.13.0.149.140", rls:"UBUNTU12.04 LTS"))) {
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
