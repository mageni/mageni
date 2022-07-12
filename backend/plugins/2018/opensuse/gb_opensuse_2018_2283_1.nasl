###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2283_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for ceph openSUSE-SU-2018:2283-1 (ceph)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851846");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-08-10 06:01:00 +0200 (Fri, 10 Aug 2018)");
  script_cve_id("CVE-2018-10861", "CVE-2018-1128", "CVE-2018-1129");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for ceph openSUSE-SU-2018:2283-1 (ceph)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for ceph fixes the following issues:

  Security issues fixed:

  - CVE-2018-10861: Ensure that ceph-mon does perform authorization on all
  OSD pool ops (bsc#1099162)

  - CVE-2018-1129: cephx signature check bypass (bsc#1096748)

  - CVE-2018-1128: cephx protocol was vulnerable to replay attack
  (bsc#1096748)

  Bugs fixed in 12.2.7-420-gc0ef85b854:

  - luminous: osd: eternal stuck PG in 'unfound_recovery' (bsc#1094932)

  - bluestore: db.slow used when db is not full (bsc#1092874)

  - Upstream fixes and improvements, see the linked references.

  This update was imported from the SUSE:SLE-12-SP3:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-854=1");
  script_tag(name:"affected", value:"ceph on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-08/msg00029.html");
  script_xref(name:"URL", value:"https://ceph.com/releases/12-2-7-luminous-released/");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"ceph", rpm:"ceph~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-base", rpm:"ceph-base~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-base-debuginfo", rpm:"ceph-base-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-common", rpm:"ceph-common~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-common-debuginfo", rpm:"ceph-common-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-debugsource", rpm:"ceph-debugsource~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-fuse", rpm:"ceph-fuse~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-fuse-debuginfo", rpm:"ceph-fuse-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-mds", rpm:"ceph-mds~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-mds-debuginfo", rpm:"ceph-mds-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-mgr", rpm:"ceph-mgr~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-mgr-debuginfo", rpm:"ceph-mgr-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-mon", rpm:"ceph-mon~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-mon-debuginfo", rpm:"ceph-mon-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-osd", rpm:"ceph-osd~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-osd-debuginfo", rpm:"ceph-osd-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-radosgw", rpm:"ceph-radosgw~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-radosgw-debuginfo", rpm:"ceph-radosgw-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-resource-agents", rpm:"ceph-resource-agents~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-test", rpm:"ceph-test~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-test-debuginfo", rpm:"ceph-test-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ceph-test-debugsource", rpm:"ceph-test-debugsource~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcephfs-devel", rpm:"libcephfs-devel~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcephfs2", rpm:"libcephfs2~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcephfs2-debuginfo", rpm:"libcephfs2-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librados-devel", rpm:"librados-devel~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librados-devel-debuginfo", rpm:"librados-devel-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librados2", rpm:"librados2~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librados2-debuginfo", rpm:"librados2-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libradosstriper-devel", rpm:"libradosstriper-devel~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libradosstriper1", rpm:"libradosstriper1~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libradosstriper1-debuginfo", rpm:"libradosstriper1-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librbd-devel", rpm:"librbd-devel~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librbd1", rpm:"librbd1~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librbd1-debuginfo", rpm:"librbd1-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librgw-devel", rpm:"librgw-devel~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librgw2", rpm:"librgw2~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librgw2-debuginfo", rpm:"librgw2-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-ceph-compat", rpm:"python-ceph-compat~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-cephfs", rpm:"python-cephfs~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-cephfs-debuginfo", rpm:"python-cephfs-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-rados", rpm:"python-rados~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-rados-debuginfo", rpm:"python-rados-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-rbd", rpm:"python-rbd~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-rbd-debuginfo", rpm:"python-rbd-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-rgw", rpm:"python-rgw~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-rgw-debuginfo", rpm:"python-rgw-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-ceph-argparse", rpm:"python3-ceph-argparse~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-cephfs", rpm:"python3-cephfs~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-cephfs-debuginfo", rpm:"python3-cephfs-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-rados", rpm:"python3-rados~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-rados-debuginfo", rpm:"python3-rados-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-rbd", rpm:"python3-rbd~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-rbd-debuginfo", rpm:"python3-rbd-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-rgw", rpm:"python3-rgw~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-rgw-debuginfo", rpm:"python3-rgw-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rados-objclass-devel", rpm:"rados-objclass-devel~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rbd-fuse", rpm:"rbd-fuse~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rbd-fuse-debuginfo", rpm:"rbd-fuse-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rbd-mirror", rpm:"rbd-mirror~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rbd-mirror-debuginfo", rpm:"rbd-mirror-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rbd-nbd", rpm:"rbd-nbd~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"d-nbd-debuginfo", rpm:"d-nbd-debuginfo~12.2.7+git.1531910353.c0ef85b854~12.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
