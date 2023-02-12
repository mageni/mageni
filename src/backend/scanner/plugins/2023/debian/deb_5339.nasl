# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.705339");
  script_version("2023-02-06T10:09:59+0000");
  script_cve_id("CVE-2023-24038");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-02-06 10:09:59 +0000 (Mon, 06 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-06 02:00:04 +0000 (Mon, 06 Feb 2023)");
  script_name("Debian: Security Advisory for libhtml-stripscripts-perl (DSA-5339-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5339.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5339-1");
  script_xref(name:"Advisory-ID", value:"DSA-5339-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libhtml-stripscripts-perl'
  package(s) announced via the DSA-5339-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ikeda Soji reported that libhtml-stripscripts-perl, a Perl module for
removing scripts from HTML, is prone to a regular expression denial of
service, due to catastrophic backtracking for HTML content with
specially crafted style attributes.");

  script_tag(name:"affected", value:"'libhtml-stripscripts-perl' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), this problem has been fixed in
version 1.06-1+deb11u1.

We recommend that you upgrade your libhtml-stripscripts-perl packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libhtml-stripscripts-perl", ver:"1.06-1+deb11u1", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
