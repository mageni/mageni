# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.853105");
  script_version("2020-04-21T09:23:28+0000");
  script_cve_id("CVE-2020-1759", "CVE-2020-1760");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-04-21 10:11:05 +0000 (Tue, 21 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-11 03:00:35 +0000 (Sat, 11 Apr 2020)");
  script_name("openSUSE: Security Advisory for ceph (openSUSE-SU-2020:0494-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-04/msg00013.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph'
  package(s) announced via the openSUSE-SU-2020:0494-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ceph fixes the following issues:

  - CVE-2020-1759: Fixed once reuse in msgr V2 secure mode (bsc#1166403)

  - CVE-2020-1760: Fixed XSS due to RGW GetObject header-splitting
  (bsc#1166484).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-494=1");

  script_tag(name:"affected", value:"'ceph' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"ceph-dashboard-e2e", rpm:"ceph-dashboard-e2e~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-grafana-dashboards", rpm:"ceph-grafana-dashboards~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mgr-dashboard", rpm:"ceph-mgr-dashboard~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mgr-diskprediction-cloud", rpm:"ceph-mgr-diskprediction-cloud~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mgr-diskprediction-local", rpm:"ceph-mgr-diskprediction-local~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mgr-k8sevents", rpm:"ceph-mgr-k8sevents~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mgr-rook", rpm:"ceph-mgr-rook~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mgr-ssh", rpm:"ceph-mgr-ssh~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-prometheus-alerts", rpm:"ceph-prometheus-alerts~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph", rpm:"ceph~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-base", rpm:"ceph-base~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-base-debuginfo", rpm:"ceph-base-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-common", rpm:"ceph-common~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-common-debuginfo", rpm:"ceph-common-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-debugsource", rpm:"ceph-debugsource~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-fuse", rpm:"ceph-fuse~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-fuse-debuginfo", rpm:"ceph-fuse-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mds", rpm:"ceph-mds~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mds-debuginfo", rpm:"ceph-mds-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mgr", rpm:"ceph-mgr~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mgr-debuginfo", rpm:"ceph-mgr-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mon", rpm:"ceph-mon~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mon-debuginfo", rpm:"ceph-mon-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-osd", rpm:"ceph-osd~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-osd-debuginfo", rpm:"ceph-osd-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-radosgw", rpm:"ceph-radosgw~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-radosgw-debuginfo", rpm:"ceph-radosgw-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-resource-agents", rpm:"ceph-resource-agents~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-test", rpm:"ceph-test~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-test-debuginfo", rpm:"ceph-test-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-test-debugsource", rpm:"ceph-test-debugsource~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cephfs-shell", rpm:"cephfs-shell~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs-devel", rpm:"libcephfs-devel~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2", rpm:"libcephfs2~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2-debuginfo", rpm:"libcephfs2-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados-devel", rpm:"librados-devel~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados-devel-debuginfo", rpm:"librados-devel-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2", rpm:"librados2~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2-debuginfo", rpm:"librados2-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradospp-devel", rpm:"libradospp-devel~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradosstriper-devel", rpm:"libradosstriper-devel~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradosstriper1", rpm:"libradosstriper1~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradosstriper1-debuginfo", rpm:"libradosstriper1-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd-devel", rpm:"librbd-devel~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1", rpm:"librbd1~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1-debuginfo", rpm:"librbd1-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw-devel", rpm:"librgw-devel~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2", rpm:"librgw2~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2-debuginfo", rpm:"librgw2-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ceph-argparse", rpm:"python3-ceph-argparse~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cephfs", rpm:"python3-cephfs~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cephfs-debuginfo", rpm:"python3-cephfs-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rados", rpm:"python3-rados~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rados-debuginfo", rpm:"python3-rados-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rbd", rpm:"python3-rbd~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rbd-debuginfo", rpm:"python3-rbd-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rgw", rpm:"python3-rgw~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rgw-debuginfo", rpm:"python3-rgw-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rados-objclass-devel", rpm:"rados-objclass-devel~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbd-fuse", rpm:"rbd-fuse~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbd-fuse-debuginfo", rpm:"rbd-fuse-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbd-mirror", rpm:"rbd-mirror~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbd-mirror-debuginfo", rpm:"rbd-mirror-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbd-nbd", rpm:"rbd-nbd~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"d-nbd-debuginfo", rpm:"d-nbd-debuginfo~14.2.5.389+gb0f23ac248~lp151.2.13.1", rls:"openSUSELeap15.1"))) {
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