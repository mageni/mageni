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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2018.3742.3");
  script_cve_id("CVE-2017-18344", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5390", "CVE-2018-5391");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-16T08:45:11+0000");
  script_tag(name:"last_modification", value:"2022-09-16 08:45:11 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-21 16:00:00 +0000 (Thu, 21 Mar 2019)");

  script_name("Ubuntu: Security Advisory (USN-3742-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3742-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3742-3");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1787258");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1787127");
  script_xref(name:"URL", value:"https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/L1TF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-trusty' package(s) announced via the USN-3742-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3742-2 introduced mitigations in the Linux Hardware Enablement
(HWE) kernel for Ubuntu 12.04 ESM to address L1 Terminal Fault (L1TF)
vulnerabilities (CVE-2018-3620, CVE-2018-3646). Unfortunately, the
update introduced regressions that caused kernel panics when booting
in some environments as well as preventing Java applications from
starting. This update fixes the problems.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that memory present in the L1 data cache of an Intel CPU
 core may be exposed to a malicious process that is executing on the CPU
 core. This vulnerability is also known as L1 Terminal Fault (L1TF). A local
 attacker in a guest virtual machine could use this to expose sensitive
 information (memory from other guests or the host OS). (CVE-2018-3646)

 It was discovered that memory present in the L1 data cache of an Intel CPU
 core may be exposed to a malicious process that is executing on the CPU
 core. This vulnerability is also known as L1 Terminal Fault (L1TF). A local
 attacker could use this to expose sensitive information (memory from the
 kernel or other processes). (CVE-2018-3620)

 Andrey Konovalov discovered an out-of-bounds read in the POSIX
 timers subsystem in the Linux kernel. A local attacker could use
 this to cause a denial of service (system crash) or expose sensitive
 information. (CVE-2017-18344)

 Juha-Matti Tilli discovered that the TCP implementation in the Linux kernel
 performed algorithmically expensive operations in some situations when
 handling incoming packets. A remote attacker could use this to cause a
 denial of service. (CVE-2018-5390)

 Juha-Matti Tilli discovered that the IP implementation in the Linux kernel
 performed algorithmically expensive operations in some situations when
 handling incoming packet fragments. A remote attacker could use this to
 cause a denial of service. (CVE-2018-5391)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-156-generic-lpae", ver:"3.13.0-156.206~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-156-generic", ver:"3.13.0-156.206~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-lts-trusty", ver:"3.13.0.156.146", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-trusty", ver:"3.13.0.156.146", rls:"UBUNTU12.04 LTS"))) {
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
