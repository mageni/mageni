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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4501.1");
  script_cve_id("CVE-2021-3979");
  script_tag(name:"creation_date", value:"2022-12-16 04:20:22 +0000 (Fri, 16 Dec 2022)");
  script_version("2022-12-16T04:20:22+0000");
  script_tag(name:"last_modification", value:"2022-12-16 04:20:22 +0000 (Fri, 16 Dec 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-31 14:42:00 +0000 (Wed, 31 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4501-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4501-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224501-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph' package(s) announced via the SUSE-SU-2022:4501-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ceph fixes the following issues:

ceph was updated to the Pacific release (16.2.9-536-g41a9f9a5573):

(bsc#1195359, bsc#1200553) rgw: check bucket shard init status in
 RGWRadosBILogTrimCR

(bsc#1194131) ceph-volume: honour osd_dmcrypt_key_size option
 (CVE-2021-3979)

(bsc#1200064,) Remove last vestiges of docker.io image paths

(bsc#1196044) cephadm: prometheus: The generatorURL in alerts is only
 using hostname

(bsc#1196785) cephadm: avoid crashing on expected non-zero exit

(jsc#SES-2515) High-availability NFS export

(bsc#1194875) [SES7P] include/buffer: include

cephadm: update image paths to registry.suse.com

cephadm: use snmp-notifier image from registry.suse.de

cephadm: infer the default container image during pull

mgr/cephadm: try to get FQDN for inventory address

(bsc#1194875) common: fix FTBFS due to dout & need_dynamic on GCC-12

(bsc#1196938) cephadm: preserve authorized_keys file during upgrade

Update Prometheus Container image paths (pr #459)

mgr/dashboard: Fix documentation URL (pr #456)

mgr/dashboard: Adapt downstream branded navigation page (pr #454)

Update prometheus-server version

(bsc#1194353) Downstream branding breaks dashboard npm build

(bsc#1178073) mgr/dashboard: fix downstream NFS doc links");

  script_tag(name:"affected", value:"'ceph' package(s) on SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Basesystem 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"ceph-common", rpm:"ceph-common~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-common-debuginfo", rpm:"ceph-common-debuginfo~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-debugsource", rpm:"ceph-debugsource~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fmt-debugsource", rpm:"fmt-debugsource~8.0.1~150300.7.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs-devel", rpm:"libcephfs-devel~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2", rpm:"libcephfs2~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2-debuginfo", rpm:"libcephfs2-debuginfo~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfmt8", rpm:"libfmt8~8.0.1~150300.7.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfmt8-debuginfo", rpm:"libfmt8-debuginfo~8.0.1~150300.7.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados-devel", rpm:"librados-devel~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados-devel-debuginfo", rpm:"librados-devel-debuginfo~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2", rpm:"librados2~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2-debuginfo", rpm:"librados2-debuginfo~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradospp-devel", rpm:"libradospp-devel~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd-devel", rpm:"librbd-devel~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1", rpm:"librbd1~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1-debuginfo", rpm:"librbd1-debuginfo~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw-devel", rpm:"librgw-devel~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2", rpm:"librgw2~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2-debuginfo", rpm:"librgw2-debuginfo~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ceph-argparse", rpm:"python3-ceph-argparse~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ceph-common", rpm:"python3-ceph-common~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cephfs", rpm:"python3-cephfs~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cephfs-debuginfo", rpm:"python3-cephfs-debuginfo~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rados", rpm:"python3-rados~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rados-debuginfo", rpm:"python3-rados-debuginfo~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rbd", rpm:"python3-rbd~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rbd-debuginfo", rpm:"python3-rbd-debuginfo~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rgw", rpm:"python3-rgw~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rgw-debuginfo", rpm:"python3-rgw-debuginfo~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rados-objclass-devel", rpm:"rados-objclass-devel~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbd-nbd", rpm:"rbd-nbd~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbd-nbd-debuginfo", rpm:"rbd-nbd-debuginfo~16.2.9.536+g41a9f9a5573~150300.6.3.1", rls:"SLES15.0SP3"))) {
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
