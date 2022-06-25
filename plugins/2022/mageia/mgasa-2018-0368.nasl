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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0368");
  script_cve_id("CVE-2017-13755", "CVE-2017-13756", "CVE-2017-13760", "CVE-2018-11737", "CVE-2018-11738", "CVE-2018-11739", "CVE-2018-11740");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-13 14:24:00 +0000 (Fri, 13 Jul 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0368)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0368");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0368.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23501");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/VEGCW34ZQ2RZ3OUDKF3BGXNLDPAIX6YM/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sleuthkit' package(s) announced via the MGASA-2018-0368 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated sleuthkit packages fix security vulnerabilities:

In The Sleuth Kit (TSK) 4.4.2, opening a crafted ISO 9660 image triggers
an out-of-bounds read in iso9660_proc_dir() in tsk/fs/iso9660_dent.c in
libtskfs.a, as demonstrated by fls (CVE-2017-13755).

In The Sleuth Kit (TSK) 4.4.2, opening a crafted disk image triggers
infinite recursion in dos_load_ext_table() in tsk/vs/dos.c in libtskvs.a,
as demonstrated by mmls (CVE-2017-13756).

In The Sleuth Kit (TSK) 4.4.2, fls hangs on a corrupt exfat image in
tsk_img_read() in tsk/img/img_io.c in libtskimg.a (CVE-2017-13760).

An issue was discovered in libtskfs.a in The Sleuth Kit (TSK) from release
4.0.2 through to 4.6.1. An out-of-bounds read of a memory region was found
in the function ntfs_fix_idxrec in tsk/fs/ntfs_dent.cpp which could be
leveraged by an attacker to disclose information or manipulated to read
from unmapped memory causing a denial of service (CVE-2018-11737).

An issue was discovered in libtskfs.a in The Sleuth Kit (TSK) from release
4.0.2 through to 4.6.1. An out-of-bounds read of a memory region was found
in the function ntfs_make_data_run in tsk/fs/ntfs.c which could be
leveraged by an attacker to disclose information or manipulated to read
from unmapped memory causing a denial of service attack (CVE-2018-11738).

An issue was discovered in libtskimg.a in The Sleuth Kit (TSK) from release
4.0.2 through to 4.6.1. An out-of-bounds read of a memory region was found
in the function raw_read in tsk/img/raw.c which could be leveraged by an
attacker to disclose information or manipulated to read from unmapped
memory causing a denial of service attack (CVE-2018-11739).

An issue was discovered in libtskbase.a in The Sleuth Kit (TSK) from
release 4.0.2 through to 4.6.1. An out-of-bounds read of a memory region
was found in the function tsk_UTF16toUTF8 in tsk/base/tsk_unicode.c which
could be leveraged by an attacker to disclose information or manipulated
to read from unmapped memory causing a denial of service attack
(CVE-2018-11740).");

  script_tag(name:"affected", value:"'sleuthkit' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64tsk-devel", rpm:"lib64tsk-devel~4.6.2~2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tsk13", rpm:"lib64tsk13~4.6.2~2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsk-devel", rpm:"libtsk-devel~4.6.2~2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtsk13", rpm:"libtsk13~4.6.2~2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sleuthkit", rpm:"sleuthkit~4.6.2~2.mga6", rls:"MAGEIA6"))) {
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
