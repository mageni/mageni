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
  script_oid("1.3.6.1.4.1.25623.1.0.892936");
  script_version("2022-03-21T14:03:47+0000");
  script_cve_id("CVE-2018-10887", "CVE-2018-10888", "CVE-2018-15501", "CVE-2018-8098", "CVE-2018-8099", "CVE-2019-1352", "CVE-2019-1353", "CVE-2020-12278", "CVE-2020-12279");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-03-22 11:26:02 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-28 01:15:00 +0000 (Tue, 28 Jan 2020)");
  script_tag(name:"creation_date", value:"2022-03-21 02:00:15 +0000 (Mon, 21 Mar 2022)");
  script_name("Debian LTS: Security Advisory for libgit2 (DLA-2936-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/03/msg00031.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2936-1");
  script_xref(name:"Advisory-ID", value:"DLA-2936-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/892961");
  script_xref(name:"URL", value:"https://bugs.debian.org/892962");
  script_xref(name:"URL", value:"https://bugs.debian.org/903508");
  script_xref(name:"URL", value:"https://bugs.debian.org/903509");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgit2'
  package(s) announced via the DLA-2936-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in libgit2, a low-level Git library,
and are as follows:

CVE-2018-8098

Integer overflow in the index.c:read_entry() function while
decompressing a compressed prefix length in libgit2 before
v0.26.2 allows an attacker to cause a denial of service
(out-of-bounds read) via a crafted repository index file.

CVE-2018-8099

Incorrect returning of an error code in the index.c:read_entry()
function leads to a double free in libgit2 before v0.26.2, which
allows an attacker to cause a denial of service via a crafted
repository index file.

CVE-2018-10887

It has been discovered that an unexpected sign extension in
git_delta_apply function in delta-apply.c file may lead to an
integer overflow which in turn leads to an out of bound read,
allowing to read before the base object. An attacker may use
this flaw to leak memory addresses or cause a Denial of Service.

CVE-2018-10888

A missing check in git_delta_apply function in delta-apply.c file,
may lead to an out-of-bound read while reading a binary delta file.
An attacker may use this flaw to cause a Denial of Service.

CVE-2018-15501

In ng_pkt in transports/smart_pkt.c in libgit2, a remote attacker
can send a crafted smart-protocol 'ng' packet that lacks a '\0'
byte to trigger an out-of-bounds read that leads to DoS.

CVE-2020-12278

path.c mishandles equivalent filenames that exist because of NTFS
Alternate Data Streams. This may allow remote code execution when
cloning a repository. This issue is similar to CVE-2019-1352.

CVE-2020-12279

checkout.c mishandles equivalent filenames that exist because of
NTFS short names. This may allow remote code execution when cloning
a repository. This issue is similar to CVE-2019-1353.");

  script_tag(name:"affected", value:"'libgit2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
0.25.1+really0.24.6-1+deb9u1.

We recommend that you upgrade your libgit2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libgit2-24", ver:"0.25.1+really0.24.6-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libgit2-dev", ver:"0.25.1+really0.24.6-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
