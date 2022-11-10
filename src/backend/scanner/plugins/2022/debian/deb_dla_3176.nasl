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
  script_oid("1.3.6.1.4.1.25623.1.0.893176");
  script_version("2022-11-09T08:42:14+0000");
  script_cve_id("CVE-2021-42387", "CVE-2021-42388", "CVE-2021-43304", "CVE-2021-43305");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-11-09 08:42:14 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-22 15:02:00 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-11-05 02:00:12 +0000 (Sat, 05 Nov 2022)");
  script_name("Debian LTS: Security Advisory for clickhouse (DLA-3176-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/11/msg00002.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3176-1");
  script_xref(name:"Advisory-ID", value:"DLA-3176-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1008216");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clickhouse'
  package(s) announced via the DLA-3176-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities were discovered in clickhouse, a
column-oriented database system.

The vulnerabilities require authentication, but can be triggered by any user
with read permissions. This means the attacker must perform reconnaissance on
the specific ClickHouse server target to obtain valid credentials. Any set of
credentials would do, since even a user with the lowest privileges can trigger
all of the vulnerabilities. By triggering the vulnerabilities, an attacker can
crash the ClickHouse server, leak memory contents or even cause remote code
execution.

CVE-2021-42387:
Heap out-of-bounds read in Clickhouse's LZ4 compression codec when
parsing a malicious query. As part of the LZ4::decompressImpl() loop,
a 16-bit unsigned user-supplied value ('offset') is read from the
compressed data. The offset is later used in the length of a copy
operation, without checking the upper bounds of the source of the copy
operation.

CVE-2021-42388:
Heap out-of-bounds read in Clickhouse's LZ4 compression codec when
parsing a malicious query. As part of the LZ4::decompressImpl() loop,
a 16-bit unsigned user-supplied value ('offset') is read from the
compressed data. The offset is later used in the length of a copy
operation, without checking the lower bounds of the source of the copy
operation.

CVE-2021-43304:
Heap buffer overflow in Clickhouse's LZ4 compression codec when
parsing a malicious query. There is no verification that the copy
operations in the LZ4::decompressImpl loop and especially the
arbitrary copy operation 'wildCopy<copy_amount>(op, ip,
copy_end)', don't exceed the destination buffer's
limits.

CVE-2021-43305:
Heap buffer overflow in Clickhouse's LZ4 compression codec when
parsing a malicious query. There is no verification that the copy
operations in the LZ4::decompressImpl loop and especially the
arbitrary copy operation 'wildCopy<copy_amount>(op, ip,
copy_end)', don't exceed the destination buffer's
limits. This issue is very similar to CVE-2021-43304, but the
vulnerable copy operation is in a different wildCopy call.");

  script_tag(name:"affected", value:"'clickhouse' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
18.16.1+ds-4+deb10u1.

We recommend that you upgrade your clickhouse packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"clickhouse-client", ver:"18.16.1+ds-4+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"clickhouse-common", ver:"18.16.1+ds-4+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"clickhouse-server", ver:"18.16.1+ds-4+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"clickhouse-tools", ver:"18.16.1+ds-4+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
