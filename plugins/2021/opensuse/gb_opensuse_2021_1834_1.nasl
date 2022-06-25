# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853918");
  script_version("2021-07-23T08:38:39+0000");
  script_cve_id("CVE-2021-3509", "CVE-2021-3524", "CVE-2021-3531");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-07-26 10:31:37 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-13 03:03:12 +0000 (Tue, 13 Jul 2021)");
  script_name("openSUSE: Security Advisory for ceph (openSUSE-SU-2021:1834-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1834-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OD76XLAQUNHRCX53LARPKA7IODR5MCPO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph'
  package(s) announced via the openSUSE-SU-2021:1834-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ceph fixes the following issues:

  - Update to 15.2.12-83-g528da226523:

  - (CVE-2021-3509) fix cookie injection issue (bsc#1186021)

  - (CVE-2021-3531) RGWSwiftWebsiteHandler::is_web_dir checks empty
       subdir_name (bsc#1186020)

  - (CVE-2021-3524) sanitize \r in s3 CORSConfigurations ExposeHeader
       (bsc#1185619)");

  script_tag(name:"affected", value:"'ceph' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"ceph", rpm:"ceph~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-base", rpm:"ceph-base~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-base-debuginfo", rpm:"ceph-base-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-common", rpm:"ceph-common~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-common-debuginfo", rpm:"ceph-common-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-debugsource", rpm:"ceph-debugsource~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-fuse", rpm:"ceph-fuse~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-fuse-debuginfo", rpm:"ceph-fuse-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-immutable-object-cache", rpm:"ceph-immutable-object-cache~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-immutable-object-cache-debuginfo", rpm:"ceph-immutable-object-cache-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mds", rpm:"ceph-mds~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mds-debuginfo", rpm:"ceph-mds-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mgr", rpm:"ceph-mgr~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mgr-debuginfo", rpm:"ceph-mgr-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mon", rpm:"ceph-mon~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mon-debuginfo", rpm:"ceph-mon-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-osd", rpm:"ceph-osd~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-osd-debuginfo", rpm:"ceph-osd-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-radosgw", rpm:"ceph-radosgw~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-radosgw-debuginfo", rpm:"ceph-radosgw-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cephfs-shell", rpm:"cephfs-shell~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs-devel", rpm:"libcephfs-devel~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2", rpm:"libcephfs2~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2-debuginfo", rpm:"libcephfs2-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados-devel", rpm:"librados-devel~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados-devel-debuginfo", rpm:"librados-devel-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2", rpm:"librados2~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2-debuginfo", rpm:"librados2-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradospp-devel", rpm:"libradospp-devel~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd-devel", rpm:"librbd-devel~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1", rpm:"librbd1~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1-debuginfo", rpm:"librbd1-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw-devel", rpm:"librgw-devel~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2", rpm:"librgw2~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2-debuginfo", rpm:"librgw2-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ceph-argparse", rpm:"python3-ceph-argparse~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ceph-common", rpm:"python3-ceph-common~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cephfs", rpm:"python3-cephfs~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cephfs-debuginfo", rpm:"python3-cephfs-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rados", rpm:"python3-rados~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rados-debuginfo", rpm:"python3-rados-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rbd", rpm:"python3-rbd~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rbd-debuginfo", rpm:"python3-rbd-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rgw", rpm:"python3-rgw~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rgw-debuginfo", rpm:"python3-rgw-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rados-objclass-devel", rpm:"rados-objclass-devel~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbd-fuse", rpm:"rbd-fuse~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbd-fuse-debuginfo", rpm:"rbd-fuse-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbd-mirror", rpm:"rbd-mirror~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbd-mirror-debuginfo", rpm:"rbd-mirror-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbd-nbd", rpm:"rbd-nbd~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbd-nbd-debuginfo", rpm:"rbd-nbd-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-test", rpm:"ceph-test~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-test-debuginfo", rpm:"ceph-test-debuginfo~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-test-debugsource", rpm:"ceph-test-debugsource~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-grafana-dashboards", rpm:"ceph-grafana-dashboards~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mgr-cephadm", rpm:"ceph-mgr-cephadm~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mgr-dashboard", rpm:"ceph-mgr-dashboard~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mgr-diskprediction-cloud", rpm:"ceph-mgr-diskprediction-cloud~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mgr-diskprediction-local", rpm:"ceph-mgr-diskprediction-local~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mgr-k8sevents", rpm:"ceph-mgr-k8sevents~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mgr-modules-core", rpm:"ceph-mgr-modules-core~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mgr-rook", rpm:"ceph-mgr-rook~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-prometheus-alerts", rpm:"ceph-prometheus-alerts~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cephadm", rpm:"cephadm~15.2.12.83+g528da226523~3.25.1", rls:"openSUSELeap15.3"))) {
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