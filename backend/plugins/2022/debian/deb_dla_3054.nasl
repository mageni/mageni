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
  script_oid("1.3.6.1.4.1.25623.1.0.893054");
  script_version("2022-06-24T14:04:41+0000");
  script_cve_id("CVE-2017-13755", "CVE-2017-13756", "CVE-2017-13760", "CVE-2018-19497", "CVE-2019-1010065", "CVE-2020-10232");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-06-24 14:04:41 +0000 (Fri, 24 Jun 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-17 06:15:00 +0000 (Sun, 17 May 2020)");
  script_tag(name:"creation_date", value:"2022-06-21 01:00:18 +0000 (Tue, 21 Jun 2022)");
  script_name("Debian LTS: Security Advisory for sleuthkit (DLA-3054-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/06/msg00015.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3054-1");
  script_xref(name:"Advisory-ID", value:"DLA-3054-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sleuthkit'
  package(s) announced via the DLA-3054-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Brief introduction 

CVE-2017-13755

Opening a crafted ISO 9660 image triggers an out-of-bounds
read in iso9660_proc_dir() in tsk/fs/iso9660_dent.c in libtskfs.a, as
demonstrated by fls.

CVE-2017-13756

Opening a crafted disk image triggers infinite recursion in
dos_load_ext_table() in tsk/vs/dos.c in libtskvs.a, as demonstrated by
mmls.

CVE-2017-13760

fls hangs on a corrupt exfat image in tsk_img_read() in
tsk/img/img_io.c in libtskimg.a.

CVE-2018-19497

In The Sleuth Kit (TSK) through 4.6.4, hfs_cat_traverse in
tsk/fs/hfs.c does not properly determine when a key length is too large,
which allows attackers to cause a denial of service (SEGV on unknown
address with READ memory access in a tsk_getu16 call in
hfs_dir_open_meta_cb in tsk/fs/hfs_dent.c).

CVE-2020-10232

Prevent a stack buffer overflow in yaffsfs_istat by
increasing the buffer size to the size required by tsk_fs_time_to_str.

CVE-2019-1010065

The Sleuth Kit 4.6.0 and earlier is affected by: Integer
Overflow. The impact is: Opening crafted disk image triggers crash in
tsk/fs/hfs_dent.c:237. The component is: Overflow in fls tool used on HFS
image. Bug is in tsk/fs/hfs.c file in function hfs_cat_traverse() in lines:
952, 1062. The attack vector is: Victim must open a crafted HFS filesystem
image.");

  script_tag(name:"affected", value:"'sleuthkit' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
4.4.0-5+deb9u1.

We recommend that you upgrade your sleuthkit packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libtsk-dev", ver:"4.4.0-5+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtsk13", ver:"4.4.0-5+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sleuthkit", ver:"4.4.0-5+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
