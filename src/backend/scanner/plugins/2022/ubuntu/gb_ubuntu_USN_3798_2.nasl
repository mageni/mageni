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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2018.3798.2");
  script_cve_id("CVE-2015-8539", "CVE-2016-7913", "CVE-2017-0794", "CVE-2017-15299", "CVE-2017-18216", "CVE-2018-1000004", "CVE-2018-7566", "CVE-2018-9518");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-14 23:29:00 +0000 (Tue, 14 May 2019)");

  script_name("Ubuntu: Security Advisory (USN-3798-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3798-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3798-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-trusty' package(s) announced via the USN-3798-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3798-1 fixed vulnerabilities in the Linux kernel for Ubuntu 14.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 14.04 LTS for Ubuntu
12.04 LTS.

Dmitry Vyukov discovered that the key management subsystem in the Linux
kernel did not properly restrict adding a key that already exists but is
negatively instantiated. A local attacker could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2015-8539)

It was discovered that a use-after-free vulnerability existed in the device
driver for XCeive xc2028/xc3028 tuners in the Linux kernel. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2016-7913)

Pengfei Ding (Ding Peng Fei ), Chenfu Bao (Bao Chen Fu ), and Lenx Wei (Wei Tao )
discovered a race condition in the generic SCSI driver (sg) of the Linux
kernel. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2017-0794)

Eric Biggers discovered that the key management subsystem in the Linux
kernel did not properly restrict adding a key that already exists but is
uninstantiated. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2017-15299)

It was discovered that a NULL pointer dereference could be triggered in the
OCFS2 file system implementation in the Linux kernel. A local attacker
could use this to cause a denial of service (system crash).
(CVE-2017-18216)

Luo Quan and Wei Yang discovered that a race condition existed in the
Advanced Linux Sound Architecture (ALSA) subsystem of the Linux kernel when
handling ioctl()s. A local attacker could use this to cause a denial of
service (system deadlock). (CVE-2018-1000004)

Fan Long Fei discovered that a race condition existed in the Advanced Linux
Sound Architecture (ALSA) subsystem of the Linux kernel that could lead to
a use- after-free or an out-of-bounds buffer access. A local attacker with
access to /dev/snd/seq could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2018-7566)

It was discovered that a buffer overflow existed in the NFC Logical Link
Control Protocol (llcp) implementation in the Linux kernel. An attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2018-9518)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-161-generic-lpae", ver:"3.13.0-161.211~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-161-generic", ver:"3.13.0-161.211~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-lts-trusty", ver:"3.13.0.161.151", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-trusty", ver:"3.13.0.161.151", rls:"UBUNTU12.04 LTS"))) {
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
