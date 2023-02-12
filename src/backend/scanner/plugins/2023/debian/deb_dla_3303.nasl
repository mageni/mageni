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
  script_oid("1.3.6.1.4.1.25623.1.0.893303");
  script_version("2023-01-31T10:08:41+0000");
  script_cve_id("CVE-2022-25648", "CVE-2022-46648", "CVE-2022-47318");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-27 14:59:00 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2023-01-31 02:00:27 +0000 (Tue, 31 Jan 2023)");
  script_name("Debian LTS: Security Advisory for ruby-git (DLA-3303-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00043.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3303-1");
  script_xref(name:"Advisory-ID", value:"DLA-3303-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1009926");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby-git'
  package(s) announced via the DLA-3303-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A couple of vulnerabilities were reported against ruby-git, a Ruby
interface to the Git revision control system, that could lead to a
command injection and execution of an arbitrary ruby code by having
a user to load a repository containing a specially crafted filename
to the product.");

  script_tag(name:"affected", value:"'ruby-git' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
1.2.8-1+deb10u1.

We recommend that you upgrade your ruby-git packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"ruby-git", ver:"1.2.8-1+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
