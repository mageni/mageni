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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3665.1");
  script_cve_id("CVE-2021-28689", "CVE-2022-26365", "CVE-2022-33740", "CVE-2022-33741", "CVE-2022-33742", "CVE-2022-33745", "CVE-2022-33746", "CVE-2022-33748");
  script_tag(name:"creation_date", value:"2022-10-20 04:46:48 +0000 (Thu, 20 Oct 2022)");
  script_version("2022-10-20T10:12:23+0000");
  script_tag(name:"last_modification", value:"2022-10-20 10:12:23 +0000 (Thu, 20 Oct 2022)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-02 18:33:00 +0000 (Tue, 02 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3665-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3665-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223665-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2022:3665-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

 - CVE-2022-33746: Fixed DoS due to excessively long P2M pool freeing
 (bsc#1203806).
 - CVE-2022-33748: Fixed DoS due to race in locking (bsc#1203807).
 - CVE-2022-26365: Fixed issue where Linux Block and Network PV device
 frontends don't zero memory regions before sharing them with the
 backend (bsc#1200762).
 - CVE-2022-33740: Fixed issue where Linux Block and Network PV device
 frontends don't zero memory regions before sharing them with the
 backend (bsc#1200762).
 - CVE-2022-33741: Fixed issue where data residing in the same 4K page as
 data shared with a backend was being accessible by such backend
 (bsc#1200762).
 - CVE-2022-33742: Fixed issue where data residing in the same 4K page as
 data shared with a backend was being accessible by such backend
 (bsc#1200762).
 - CVE-2022-33745: Fixed an insufficient TLB flush for x86 PV guests in
 shadow mode (bsc#1201394).
 - CVE-2021-28689: Fixed speculative vulnerabilities with bare (non-shim)
 32-bit PV guests (bsc#1185104).

 Bugfixes:

 - Fixed logic error in built-in default of max_event_channels
 (bsc#1167608, bsc#1201631).
 - Fixed issue where dom0 fails to boot with constrained vcpus and nodes
 (bsc#1197081).
 - Included upstream bugfixes (bsc#1027519).");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Server Applications 15-SP3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.14.5_06~150300.3.35.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.14.5_06~150300.3.35.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.14.5_06~150300.3.35.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.14.5_06~150300.3.35.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.14.5_06~150300.3.35.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.14.5_06~150300.3.35.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.14.5_06~150300.3.35.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.14.5_06~150300.3.35.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.14.5_06~150300.3.35.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-xendomains-wait-disk", rpm:"xen-tools-xendomains-wait-disk~4.14.5_06~150300.3.35.1", rls:"SLES15.0SP3"))) {
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
