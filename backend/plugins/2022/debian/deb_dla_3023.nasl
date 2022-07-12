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
  script_oid("1.3.6.1.4.1.25623.1.0.893023");
  script_version("2022-05-31T03:05:10+0000");
  script_cve_id("CVE-2019-16770", "CVE-2020-5247", "CVE-2022-23634");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-05-31 03:05:10 +0000 (Tue, 31 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-06 15:07:00 +0000 (Wed, 06 May 2020)");
  script_tag(name:"creation_date", value:"2022-05-26 01:00:11 +0000 (Thu, 26 May 2022)");
  script_name("Debian LTS: Security Advisory for puma (DLA-3023-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/05/msg00034.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3023-1");
  script_xref(name:"Advisory-ID", value:"DLA-3023-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/946312");
  script_xref(name:"URL", value:"https://bugs.debian.org/952766");
  script_xref(name:"URL", value:"https://bugs.debian.org/1005391");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'puma'
  package(s) announced via the DLA-3023-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in puma, a web server for
Ruby/Rack applications. These flaws may lead to information leakage due to not
always closing response bodies, allowing untrusted input in a response header
(HTTP Response Splitting) and thus potentially facilitating several other
attacks like cross-site scripting. A poorly-behaved client could also use
keepalive requests to monopolize Puma's reactor and create a denial of service
attack.");

  script_tag(name:"affected", value:"'puma' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
3.6.0-1+deb9u2.

We recommend that you upgrade your puma packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"puma", ver:"3.6.0-1+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
