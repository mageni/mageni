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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5541.1");
  script_cve_id("CVE-2021-4197", "CVE-2022-1011", "CVE-2022-1198", "CVE-2022-1199", "CVE-2022-1204", "CVE-2022-1205", "CVE-2022-1353", "CVE-2022-1516", "CVE-2022-2380", "CVE-2022-28388", "CVE-2022-28389");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-09 15:32:00 +0000 (Sat, 09 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-5541-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5541-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5541-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure' package(s) announced via the USN-5541-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Eric Biederman discovered that the cgroup process migration implementation
in the Linux kernel did not perform permission checks correctly in some
situations. A local attacker could possibly use this to gain administrative
privileges. (CVE-2021-4197)

Jann Horn discovered that the FUSE file system in the Linux kernel
contained a use-after-free vulnerability. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2022-1011)

Duoming Zhou discovered that the 6pack protocol implementation in the Linux
kernel did not handle detach events properly in some situations, leading to
a use-after-free vulnerability. A local attacker could use this to cause a
denial of service (system crash). (CVE-2022-1198)

Duoming Zhou discovered that the AX.25 amateur radio protocol
implementation in the Linux kernel did not handle detach events properly in
some situations. A local attacker could possibly use this to cause a denial
of service (system crash) or execute arbitrary code. (CVE-2022-1199)

Duoming Zhou discovered race conditions in the AX.25 amateur radio protocol
implementation in the Linux kernel during device detach operations. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2022-1204)

Duoming Zhou discovered race conditions in the AX.25 amateur radio protocol
implementation in the Linux kernel, leading to use-after-free
vulnerabilities. A local attacker could possibly use this to cause a denial
of service (system crash). (CVE-2022-1205)

It was discovered that the PF_KEYv2 implementation in the Linux kernel did
not properly initialize kernel memory in some situations. A local attacker
could use this to expose sensitive information (kernel memory).
(CVE-2022-1353)

It was discovered that the implementation of X.25 network protocols in the
Linux kernel did not terminate link layer sessions properly. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2022-1516)

Zheyu Ma discovered that the Silicon Motion SM712 framebuffer driver in the
Linux kernel did not properly handle very small reads. A local attacker
could use this to cause a denial of service (system crash). (CVE-2022-2380)

It was discovered that the 8 Devices USB2CAN interface implementation in
the Linux kernel did not properly handle certain error conditions, leading
to a double-free. A local attacker could possibly use this to cause a
denial of service (system crash). (CVE-2022-28388)

It was discovered that the Microchip CAN BUS Analyzer interface
implementation in the Linux kernel did not properly handle certain error
conditions, leading to a double-free. A local attacker could possibly use
this to cause a denial of service (system crash). (CVE-2022-28389)");

  script_tag(name:"affected", value:"'linux-azure' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1146-azure", ver:"4.15.0-1146.161~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"4.15.0.1146.133", rls:"UBUNTU16.04 LTS"))) {
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
