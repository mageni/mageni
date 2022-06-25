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
  script_oid("1.3.6.1.4.1.25623.1.0.892810");
  script_version("2021-11-15T09:54:42+0000");
  script_cve_id("CVE-2021-32626", "CVE-2021-32672", "CVE-2021-32675", "CVE-2021-32687", "CVE-2021-32762", "CVE-2021-41099");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-13 17:08:00 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-11-06 02:00:20 +0000 (Sat, 06 Nov 2021)");
  script_name("Debian LTS: Security Advisory for redis (DLA-2810-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/11/msg00004.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2810-1");
  script_xref(name:"Advisory-ID", value:"DLA-2810-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis'
  package(s) announced via the DLA-2810-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were a number of issues in redis, a
popular key-value database system:

  * CVE-2021-41099: Integer to heap buffer overflow handling certain
string commands and network payloads, when proto-max-bulk-len is
manually configured to a non-default, very large value.

  * CVE-2021-32762: Integer to heap buffer overflow issue in redis-cli
and redis-sentinel parsing large multi-bulk replies on some older
and less common platforms.

  * CVE-2021-32687: Integer to heap buffer overflow with intsets, when
set-max-intset-entries is manually configured to a non-default,
very large value.

  * CVE-2021-32675: Denial Of Service when processing RESP request
payloads with a large number of elements on many connections.

  * CVE-2021-32672: Random heap reading issue with Lua Debugger.

  * CVE-2021-32626: Specially crafted Lua scripts may result with
Heap buffer overflow.");

  script_tag(name:"affected", value:"'redis' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 'Stretch', this problem has been fixed in version
3:3.2.6-3+deb9u8.

We recommend that you upgrade your redis packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"redis-sentinel", ver:"3:3.2.6-3+deb9u8", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"redis-server", ver:"3:3.2.6-3+deb9u8", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"redis-tools", ver:"3:3.2.6-3+deb9u8", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
