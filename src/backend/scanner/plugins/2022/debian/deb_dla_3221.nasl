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
  script_oid("1.3.6.1.4.1.25623.1.0.893221");
  script_version("2022-12-06T10:11:16+0000");
  script_cve_id("CVE-2018-16472", "CVE-2021-23518");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-12-06 10:11:16 +0000 (Tue, 06 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-27 19:27:00 +0000 (Thu, 27 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-12-05 02:00:13 +0000 (Mon, 05 Dec 2022)");
  script_name("Debian LTS: Security Advisory for node-cached-path-relative (DLA-3221-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/12/msg00006.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3221-1");
  script_xref(name:"Advisory-ID", value:"DLA-3221-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1004338");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'node-cached-path-relative'
  package(s) announced via the DLA-3221-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cristian-Alexandru Staicu discovered a prototype pollution vulnerability
in inode-cached-path-relative, a Node.js module used to cache (memoize)
the result of path.relative.

CVE-2018-16472

An attacker controlling both the path and the cached value, can
mount a prototype pollution attack and thus overwrite arbitrary
properties on Object.prototype, which may result in denial of
service.

CVE-2021-23518

The fix for CVE-2018-16472 was incomplete and other prototype
pollution vulnerabilities were found in the meantime, resulting in a
new CVE.");

  script_tag(name:"affected", value:"'node-cached-path-relative' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
1.0.1-2+deb10u1.

We recommend that you upgrade your node-cached-path-relative packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"node-cached-path-relative", ver:"1.0.1-2+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
