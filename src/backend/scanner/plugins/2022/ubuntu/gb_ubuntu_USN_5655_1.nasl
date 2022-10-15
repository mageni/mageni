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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5655.1");
  script_cve_id("CVE-2021-33655", "CVE-2022-2318", "CVE-2022-26365", "CVE-2022-33740", "CVE-2022-33741", "CVE-2022-33742", "CVE-2022-33743", "CVE-2022-33744", "CVE-2022-34494", "CVE-2022-34495", "CVE-2022-36946");
  script_tag(name:"creation_date", value:"2022-10-05 04:26:35 +0000 (Wed, 05 Oct 2022)");
  script_version("2022-10-05T10:13:22+0000");
  script_tag(name:"last_modification", value:"2022-10-05 10:13:22 +0000 (Wed, 05 Oct 2022)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-14 12:10:00 +0000 (Thu, 14 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-5655-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5655-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5655-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-intel-iotg' package(s) announced via the USN-5655-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the framebuffer driver on the Linux kernel did not
verify size limits when changing font or screen size, leading to an out-of-
bounds write. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2021-33655)

Duoming Zhou discovered that race conditions existed in the timer handling
implementation of the Linux kernel's Rose X.25 protocol layer, resulting in
use-after-free vulnerabilities. A local attacker could use this to cause a
denial of service (system crash). (CVE-2022-2318)

Roger Pau Monne discovered that the Xen virtual block driver in the Linux
kernel did not properly initialize memory pages to be used for shared
communication with the backend. A local attacker could use this to expose
sensitive information (guest kernel memory). (CVE-2022-26365)

Roger Pau Monne discovered that the Xen paravirtualization frontend in the
Linux kernel did not properly initialize memory pages to be used for shared
communication with the backend. A local attacker could use this to expose
sensitive information (guest kernel memory). (CVE-2022-33740)

It was discovered that the Xen paravirtualization frontend in the Linux
kernel incorrectly shared unrelated data when communicating with certain
backends. A local attacker could use this to cause a denial of service
(guest crash) or expose sensitive information (guest kernel memory).
(CVE-2022-33741, CVE-2022-33742)

Jan Beulich discovered that the Xen network device frontend driver in the
Linux kernel incorrectly handled socket buffers (skb) references when
communicating with certain backends. A local attacker could use this to
cause a denial of service (guest crash). (CVE-2022-33743)

Oleksandr Tyshchenko discovered that the Xen paravirtualization platform in
the Linux kernel on ARM platforms contained a race condition in certain
situations. An attacker in a guest VM could use this to cause a denial of
service in the host OS. (CVE-2022-33744)

It was discovered that the virtio RPMSG bus driver in the Linux kernel
contained a double-free vulnerability in certain error conditions. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2022-34494, CVE-2022-34495)

Domingo Dirutigliano and Nicola Guerrera discovered that the netfilter
subsystem in the Linux kernel did not properly handle rules that truncated
packets below the packet header size. When such rules are in place, a
remote attacker could possibly use this to cause a denial of service
(system crash). (CVE-2022-36946)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.15.0-1016-intel-iotg", ver:"5.15.0-1016.21", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-intel-iotg", ver:"5.15.0.1016.17", rls:"UBUNTU22.04 LTS"))) {
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
