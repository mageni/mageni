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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1435.1");
  script_cve_id("CVE-2022-21698");
  script_tag(name:"creation_date", value:"2022-04-28 04:44:31 +0000 (Thu, 28 Apr 2022)");
  script_version("2022-04-28T04:44:31+0000");
  script_tag(name:"last_modification", value:"2022-04-28 04:44:31 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-24 02:59:00 +0000 (Thu, 24 Feb 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1435-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1435-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221435-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firewalld, golang-github-prometheus-prometheus' package(s) announced via the SUSE-SU-2022:1435-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for firewalld, golang-github-prometheus-prometheus fixes the following issues:

Security fixes for golang-github-prometheus-prometheus:

CVE-2022-21698: Denial of Service through unbounded cardinality, and
 potential memory exhaustion, when handling requests with non-standard
 HTTP methods (bsc#1196338).

Other non security changes for golang-github-prometheus-prometheus:

Build `firewalld-prometheus-config` only for SUSE Linux Enterprise 15,
 15-SP1 and 15-SP2, and require `firewalld`.

Only recommends `firewalld-prometheus-config` as prometheus does not
 require it to run.

Create `firewalld-prometheus-config` subpackage (bsc#1197042,
 jsc#SLE-24373, jsc#SLE-24374, jsc#SLE-24375)

Other non security changes for firewalld:
Provide dummy `firewalld-prometheus-config` package (bsc#1197042)");

  script_tag(name:"affected", value:"'firewalld, golang-github-prometheus-prometheus' package(s) on SUSE Enterprise Storage 6, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Desktop Applications 15-SP3, SUSE Linux Enterprise Module for SUSE Manager Proxy 4.1, SUSE Linux Enterprise Module for SUSE Manager Proxy 4.2, SUSE Linux Enterprise Module for SUSE Manager Proxy 4.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"firewall-macros", rpm:"firewall-macros~0.9.3~150300.3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firewalld", rpm:"firewalld~0.9.3~150300.3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firewalld-lang", rpm:"firewalld-lang~0.9.3~150300.3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-firewall", rpm:"python3-firewall~0.9.3~150300.3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firewall-applet", rpm:"firewall-applet~0.9.3~150300.3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firewall-config", rpm:"firewall-config~0.9.3~150300.3.6.1", rls:"SLES15.0SP3"))) {
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
