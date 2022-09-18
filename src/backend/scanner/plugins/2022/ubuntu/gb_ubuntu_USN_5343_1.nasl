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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5343.1");
  script_cve_id("CVE-2016-2853", "CVE-2016-2854", "CVE-2018-5995", "CVE-2019-19449", "CVE-2020-12655", "CVE-2020-25670", "CVE-2020-25671", "CVE-2020-25672", "CVE-2020-25673", "CVE-2020-26139", "CVE-2020-26147", "CVE-2020-26555", "CVE-2020-26558", "CVE-2020-36322", "CVE-2020-36385", "CVE-2021-0129", "CVE-2021-20292", "CVE-2021-20317", "CVE-2021-23134", "CVE-2021-28688", "CVE-2021-28972", "CVE-2021-29650", "CVE-2021-32399", "CVE-2021-33033", "CVE-2021-33034", "CVE-2021-33098", "CVE-2021-34693", "CVE-2021-3483", "CVE-2021-3506", "CVE-2021-3564", "CVE-2021-3573", "CVE-2021-3612", "CVE-2021-3679", "CVE-2021-38160", "CVE-2021-38198", "CVE-2021-38204", "CVE-2021-38208", "CVE-2021-39648", "CVE-2021-40490", "CVE-2021-42008", "CVE-2021-43389", "CVE-2021-45095", "CVE-2021-45469", "CVE-2021-45485", "CVE-2022-0492");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-15 13:35:00 +0000 (Tue, 15 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5343-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5343-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5343-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-lts-xenial' package(s) announced via the USN-5343-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yiqi Sun and Kevin Wang discovered that the cgroups implementation in the
Linux kernel did not properly restrict access to the cgroups v1
release_agent feature. A local attacker could use this to gain
administrative privileges. (CVE-2022-0492)

It was discovered that the aufs file system in the Linux kernel did not
properly restrict mount namespaces, when mounted with the non-default
allow_userns option set. A local attacker could use this to gain
administrative privileges. (CVE-2016-2853)

It was discovered that the aufs file system in the Linux kernel did not
properly maintain POSIX ACL xattr data, when mounted with the non-default
allow_userns option. A local attacker could possibly use this to gain
elevated privileges. (CVE-2016-2854)

It was discovered that the f2fs file system in the Linux kernel did not
properly validate metadata in some situations. An attacker could use this
to construct a malicious f2fs image that, when mounted and operated on,
could cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2019-19449)

It was discovered that the XFS file system implementation in the Linux
kernel did not properly validate meta data in some circumstances. An
attacker could use this to construct a malicious XFS image that, when
mounted, could cause a denial of service. (CVE-2020-12655)

Kiyin (Yin Liang ) discovered that the NFC LLCP protocol implementation in the
Linux kernel contained a reference counting error. A local attacker could
use this to cause a denial of service (system crash). (CVE-2020-25670)

Kiyin (Yin Liang ) discovered that the NFC LLCP protocol implementation in the
Linux kernel did not properly deallocate memory in certain error
situations. A local attacker could use this to cause a denial of service
(memory exhaustion). (CVE-2020-25671, CVE-2020-25672)

Kiyin (Yin Liang ) discovered that the NFC LLCP protocol implementation in the
Linux kernel did not properly handle error conditions in some situations,
leading to an infinite loop. A local attacker could use this to cause a
denial of service. (CVE-2020-25673)

Mathy Vanhoef discovered that the Linux kernel's WiFi implementation
incorrectly handled EAPOL frames from unauthenticated senders. A physically
proximate attacker could inject malicious packets to cause a denial of
service (system crash). (CVE-2020-26139)

Mathy Vanhoef discovered that the Linux kernel's WiFi implementation could
reassemble mixed encrypted and plaintext fragments. A physically proximate
attacker could possibly use this issue to inject packets or exfiltrate
selected fragments. (CVE-2020-26147)

It was discovered that the BR/EDR pin-code pairing procedure in the Linux
kernel was vulnerable to an impersonation attack. A physically proximate
attacker could possibly use this to pair to a device without knowledge of
the pin-code. (CVE-2020-26555)

It was discovered that the bluetooth subsystem in the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-kvm, linux-lts-xenial' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1102-aws", ver:"4.4.0-1102.107", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-222-generic", ver:"4.4.0-222.255~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-222-lowlatency", ver:"4.4.0-222.255~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1102.100", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.222.193", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.222.193", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-lts-xenial", ver:"4.4.0.222.193", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1103-kvm", ver:"4.4.0-1103.112", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1138-aws", ver:"4.4.0-1138.152", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-222-generic", ver:"4.4.0-222.255", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-222-lowlatency", ver:"4.4.0-222.255", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1138.143", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.4.0.222.229", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.4.0.1103.101", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.4.0.222.229", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"4.4.0.222.229", rls:"UBUNTU16.04 LTS"))) {
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
