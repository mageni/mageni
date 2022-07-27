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
  script_oid("1.3.6.1.4.1.25623.1.0.892912");
  script_version("2022-02-07T02:00:05+0000");
  script_cve_id("CVE-2021-3850");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-02-07 11:11:48 +0000 (Mon, 07 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-07 02:00:05 +0000 (Mon, 07 Feb 2022)");
  script_name("Debian LTS: Security Advisory for libphp-adodb (DLA-2912-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/02/msg00006.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2912-1");
  script_xref(name:"Advisory-ID", value:"DLA-2912-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1004376");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libphp-adodb'
  package(s) announced via the DLA-2912-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that in libphp-adodb, a PHP database abstraction layer
library, an attacker can inject values into the PostgreSQL connection
string by bypassing adodb_addslashes(). The function can be bypassed
in phppgadmin, for example, by surrounding the username in quotes and
submitting with other parameters injected in between.");

  script_tag(name:"affected", value:"'libphp-adodb' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
5.20.9-1+deb9u1.

We recommend that you upgrade your libphp-adodb packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libphp-adodb", ver:"5.20.9-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
