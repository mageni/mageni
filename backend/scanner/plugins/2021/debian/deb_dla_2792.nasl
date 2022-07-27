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
  script_oid("1.3.6.1.4.1.25623.1.0.892792");
  script_version("2021-10-25T01:00:15+0000");
  script_cve_id("CVE-2018-20199", "CVE-2018-20360", "CVE-2019-6956", "CVE-2021-32274", "CVE-2021-32276", "CVE-2021-32277", "CVE-2021-32278");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-25 10:12:29 +0000 (Mon, 25 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-25 01:00:15 +0000 (Mon, 25 Oct 2021)");
  script_name("Debian LTS: Security Advisory for faad2 (DLA-2792-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/10/msg00020.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2792-1");
  script_xref(name:"Advisory-ID", value:"DLA-2792-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'faad2'
  package(s) announced via the DLA-2792-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been found in faad2, a freeware Advanced Audio Decoder
player. They are related to heap buffer overflows or null pointer
dereferences, which both might allow an attacker to execute code by
providing crafted files.");

  script_tag(name:"affected", value:"'faad2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2.8.0~cvs20161113-1+deb9u3.

We recommend that you upgrade your faad2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"faad", ver:"2.8.0~cvs20161113-1+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"faad2-dbg", ver:"2.8.0~cvs20161113-1+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfaad-dev", ver:"2.8.0~cvs20161113-1+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libfaad2", ver:"2.8.0~cvs20161113-1+deb9u3", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
