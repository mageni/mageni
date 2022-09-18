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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2017.3343.2");
  script_cve_id("CVE-2014-9940", "CVE-2017-0605", "CVE-2017-1000363", "CVE-2017-7294", "CVE-2017-8890", "CVE-2017-9074", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2017-9242");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3343-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3343-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3343-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1699772");
  script_xref(name:"URL", value:"https://www.ubuntu.com/usn/usn-3335-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-trusty' package(s) announced via the USN-3343-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN 3343-1 fixed vulnerabilities in the Linux kernel for Ubuntu 14.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 14.04 LTS for Ubuntu
12.04 ESM.

USN 3335-2 fixed a vulnerability in the Linux kernel. However, that
fix introduced regressions for some Java applications. This update
addresses the issue. We apologize for the inconvenience.

It was discovered that a use-after-free vulnerability in the core voltage
regulator driver of the Linux kernel. A local attacker could use this to
cause a denial of service or possibly execute arbitrary code.
(CVE-2014-9940)

It was discovered that a buffer overflow existed in the trace subsystem in
the Linux kernel. A privileged local attacker could use this to execute
arbitrary code. (CVE-2017-0605)

Roee Hay discovered that the parallel port printer driver in the Linux
kernel did not properly bounds check passed arguments. A local attacker
with write access to the kernel command line arguments could use this to
execute arbitrary code. (CVE-2017-1000363)

Li Qiang discovered that an integer overflow vulnerability existed in the
Direct Rendering Manager (DRM) driver for VMWare devices in the Linux
kernel. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2017-7294)

It was discovered that a double-free vulnerability existed in the IPv4
stack of the Linux kernel. An attacker could use this to cause a denial of
service (system crash). (CVE-2017-8890)

Andrey Konovalov discovered an IPv6 out-of-bounds read error in the Linux
kernel's IPv6 stack. A local attacker could cause a denial of service or
potentially other unspecified problems. (CVE-2017-9074)

Andrey Konovalov discovered a flaw in the handling of inheritance in the
Linux kernel's IPv6 stack. A local user could exploit this issue to cause a
denial of service or possibly other unspecified problems. (CVE-2017-9075)

It was discovered that dccp v6 in the Linux kernel mishandled inheritance.
A local attacker could exploit this issue to cause a denial of service or
potentially other unspecified problems. (CVE-2017-9076)

It was discovered that the transmission control protocol (tcp) v6 in the
Linux kernel mishandled inheritance. A local attacker could exploit this
issue to cause a denial of service or potentially other unspecified
problems. (CVE-2017-9077)

It was discovered that the IPv6 stack in the Linux kernel was performing
its over write consistency check after the data was actually overwritten. A
local attacker could exploit this flaw to cause a denial of service (system
crash). (CVE-2017-9242)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-123-generic-lpae", ver:"3.13.0-123.172~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-123-generic", ver:"3.13.0-123.172~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-lts-trusty", ver:"3.13.0.123.114", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-trusty", ver:"3.13.0.123.114", rls:"UBUNTU12.04 LTS"))) {
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
