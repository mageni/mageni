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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3928.1");
  script_cve_id("CVE-2021-28689", "CVE-2022-26363", "CVE-2022-26364", "CVE-2022-26365", "CVE-2022-33740", "CVE-2022-33741", "CVE-2022-33742", "CVE-2022-33746", "CVE-2022-33748", "CVE-2022-42309", "CVE-2022-42310", "CVE-2022-42311", "CVE-2022-42312", "CVE-2022-42313", "CVE-2022-42314", "CVE-2022-42315", "CVE-2022-42316", "CVE-2022-42317", "CVE-2022-42318", "CVE-2022-42319", "CVE-2022-42320", "CVE-2022-42321", "CVE-2022-42322", "CVE-2022-42323", "CVE-2022-42325", "CVE-2022-42326");
  script_tag(name:"creation_date", value:"2022-11-11 04:27:47 +0000 (Fri, 11 Nov 2022)");
  script_version("2022-11-11T04:27:47+0000");
  script_tag(name:"last_modification", value:"2022-11-11 04:27:47 +0000 (Fri, 11 Nov 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-03 14:50:00 +0000 (Thu, 03 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3928-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3928-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223928-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2022:3928-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

CVE-2022-33746: Fixed DoS due to excessively long P2M pool freeing
 (bsc#1203806).

CVE-2022-33748: Fixed DoS due to race in locking (bsc#1203807).

CVE-2021-28689: Fixed speculative vulnerabilities with bare (non-shim)
 32-bit PV guests (bsc#1185104).

CVE-2022-42311, CVE-2022-42312, CVE-2022-42313, CVE-2022-42314,
 CVE-2022-42315, CVE-2022-42316, CVE-2022-42317, CVE-2022-42318: xen:
 Xenstore: Guests can let xenstored run out of memory (bsc#1204482)

CVE-2022-42309: xen: Xenstore: Guests can crash xenstored (bsc#1204485)

CVE-2022-42310: xen: Xenstore: Guests can create orphaned Xenstore nodes
 (bsc#1204487)

CVE-2022-42319: xen: Xenstore: Guests can cause Xenstore to not free
 temporary memory (bsc#1204488)

CVE-2022-42320: xen: Xenstore: Guests can get access to Xenstore nodes
 of deleted domains (bsc#1204489)

CVE-2022-42321: xen: Xenstore: Guests can crash xenstored via exhausting
 the stack (bsc#1204490)

CVE-2022-42322,CVE-2022-42323: xen: Xenstore: cooperating guests can
 create arbitrary numbers of nodes (bsc#1204494)

CVE-2022-42325,CVE-2022-42326: xen: Xenstore: Guests can create arbitray
 number of nodes via transactions (bsc#1204496)

CVE-2022-26363,CVE-2022-26364: xen: Insufficient care with non-coherent
 mappings (bsc#1199966).

CVE-2022-26365,CVE-2022-33740,CVE-2022-33741,CVE-2022-33742: xen: Linux
 disk/nic frontends data leaks (bsc#1200762).

xen: Frontends vulnerable to backends (bsc#1193923).");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.12.4_30~150100.3.80.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.12.4_30~150100.3.80.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.12.4_30~150100.3.80.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.12.4_30~150100.3.80.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.12.4_30~150100.3.80.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.12.4_30~150100.3.80.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.12.4_30~150100.3.80.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.12.4_30~150100.3.80.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.12.4_30~150100.3.80.1", rls:"SLES15.0SP1"))) {
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
