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
  script_oid("1.3.6.1.4.1.25623.1.0.893055");
  script_version("2022-06-24T14:04:41+0000");
  script_cve_id("CVE-2022-30783", "CVE-2022-30784", "CVE-2022-30785", "CVE-2022-30786", "CVE-2022-30787", "CVE-2022-30788", "CVE-2022-30789");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-06-24 14:04:41 +0000 (Fri, 24 Jun 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-08 02:16:00 +0000 (Wed, 08 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-22 01:00:15 +0000 (Wed, 22 Jun 2022)");
  script_name("Debian LTS: Security Advisory for ntfs-3g (DLA-3055-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/06/msg00017.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3055-1");
  script_xref(name:"Advisory-ID", value:"DLA-3055-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1011770");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntfs-3g'
  package(s) announced via the DLA-3055-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in NTFS-3G, a read-write NTFS
driver for FUSE. A local user can take advantage of these flaws for
local root privilege escalation.

CVE-2022-30783

An invalid return code in fuse_kern_mount enables intercepting of
libfuse-lite protocol traffic between NTFS-3G and the kernel when
using libfuse-lite.

CVE-2022-30784

A crafted NTFS image can cause heap exhaustion in
ntfs_get_attribute_value.

CVE-2022-30785

A file handle created in fuse_lib_opendir, and later used in
fuse_lib_readdir, enables arbitrary memory read and write
operations when using libfuse-lite.

CVE-2022-30786

A crafted NTFS image can cause a heap-based buffer overflow in
ntfs_names_full_collate.

CVE-2022-30787

An integer underflow in fuse_lib_readdir enables arbitrary memory
read operations when using libfuse-lite.

CVE-2022-30788

A crafted NTFS image can cause a heap-based buffer overflow in
ntfs_mft_rec_alloc.

CVE-2022-30789

A crafted NTFS image can cause a heap-based buffer overflow in
ntfs_check_log_client_array.");

  script_tag(name:"affected", value:"'ntfs-3g' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1:2016.2.22AR.1+dfsg-1+deb9u3.

We recommend that you upgrade your ntfs-3g packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libntfs-3g871", ver:"1:2016.2.22AR.1+dfsg-1+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g", ver:"1:2016.2.22AR.1+dfsg-1+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g-dbg", ver:"1:2016.2.22AR.1+dfsg-1+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ntfs-3g-dev", ver:"1:2016.2.22AR.1+dfsg-1+deb9u3", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
