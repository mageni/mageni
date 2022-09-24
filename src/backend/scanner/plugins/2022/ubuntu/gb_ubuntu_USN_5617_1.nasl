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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5617.1");
  script_cve_id("CVE-2020-0543", "CVE-2020-11739", "CVE-2020-11740", "CVE-2020-11741", "CVE-2020-11742", "CVE-2020-11743", "CVE-2020-15563", "CVE-2020-15564", "CVE-2020-15565", "CVE-2020-15566", "CVE-2020-15567", "CVE-2020-25595", "CVE-2020-25596", "CVE-2020-25597", "CVE-2020-25599", "CVE-2020-25600", "CVE-2020-25601", "CVE-2020-25602", "CVE-2020-25603", "CVE-2020-25604");
  script_tag(name:"creation_date", value:"2022-09-20 04:41:34 +0000 (Tue, 20 Sep 2022)");
  script_version("2022-09-20T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-20 10:11:40 +0000 (Tue, 20 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-5617-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5617-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5617-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the USN-5617-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that memory contents previously stored in
microarchitectural special registers after RDRAND, RDSEED, and SGX EGETKEY
read operations on Intel client and Xeon E3 processors may be briefly
exposed to processes on the same or different processor cores. A local
attacker could use this to expose sensitive information. (CVE-2020-0543)

Julien Grall discovered that Xen incorrectly handled memory barriers on
ARM-based systems. An attacker could possibly use this issue to cause a
denial of service, obtain sensitive information or escalate privileges.
(CVE-2020-11739)

Ilja Van Sprundel discovered that Xen incorrectly handled profiling of
guests. An unprivileged attacker could use this issue to obtain sensitive
information from other guests, cause a denial of service or possibly gain
privileges. (CVE-2020-11740, CVE-2020-11741)

It was discovered that Xen incorrectly handled grant tables. A malicious
guest could possibly use this issue to cause a denial of service.
(CVE-2020-11742, CVE-2020-11743)

Jan Beulich discovered that Xen incorrectly handled certain code paths. An
attacker could possibly use this issue to cause a denial of service.
(CVE-2020-15563)

Julien Grall discovered that Xen incorrectly verified memory addresses
provided by the guest on ARM-based systems. A malicious guest administrator
could possibly use this issue to cause a denial of service. (CVE-2020-15564)

Roger Pau Monne discovered that Xen incorrectly handled caching on x86 Intel
systems. An attacker could possibly use this issue to cause a denial of
service. (CVE-2020-15565)

It was discovered that Xen incorrectly handled error in event-channel port
allocation. A malicious guest could possibly use this issue to cause a
denial of service. (CVE-2020-15566)

Jan Beulich discovered that Xen incorrectly handled certain EPT (Extended
Page Tables). An attacker could possibly use this issue to cause a denial
of service, data corruption or privilege escalation. (CVE-2020-15567)

Andrew Cooper discovered that Xen incorrectly handled PCI passthrough.
An attacker could possibly use this issue to cause a denial of service.
(CVE-2020-25595)

Andrew Cooper discovered that Xen incorrectly sanitized path injections.
An attacker could possibly use this issue to cause a denial of service.
(CVE-2020-25596)

Jan Beulich discovered that Xen incorrectly handled validation of event
channels. An attacker could possibly use this issue to cause a denial
of service. (CVE-2020-25597)

Julien Grall and Jan Beulich discovered that Xen incorrectly handled
resetting event channels. An attacker could possibly use this issue to
cause a denial of service or obtain sensitive information. (CVE-2020-25599)

Julien Grall discovered that Xen incorrectly handled event channels
memory allocation on 32-bits domains. An attacker could possibly use this
issue to cause a denial of service. (CVE-2020-25600)

Jan Beulich discovered that ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xen' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxendevicemodel1", ver:"4.11.3+24-g14b62ab3e5-1ubuntu2.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenevtchn1", ver:"4.11.3+24-g14b62ab3e5-1ubuntu2.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxengnttab1", ver:"4.11.3+24-g14b62ab3e5-1ubuntu2.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenmisc4.11", ver:"4.11.3+24-g14b62ab3e5-1ubuntu2.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.11-amd64", ver:"4.11.3+24-g14b62ab3e5-1ubuntu2.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.11-arm64", ver:"4.11.3+24-g14b62ab3e5-1ubuntu2.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.11-armhf", ver:"4.11.3+24-g14b62ab3e5-1ubuntu2.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.11", ver:"4.11.3+24-g14b62ab3e5-1ubuntu2.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.11.3+24-g14b62ab3e5-1ubuntu2.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.11.3+24-g14b62ab3e5-1ubuntu2.3", rls:"UBUNTU20.04 LTS"))) {
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
