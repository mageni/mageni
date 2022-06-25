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
  script_oid("1.3.6.1.4.1.25623.1.0.893035");
  script_version("2022-06-09T14:06:34+0000");
  script_cve_id("CVE-2014-10401", "CVE-2014-10402");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-06-10 10:05:32 +0000 (Fri, 10 Jun 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-30 13:47:00 +0000 (Wed, 30 Sep 2020)");
  script_tag(name:"creation_date", value:"2022-06-01 13:28:14 +0000 (Wed, 01 Jun 2022)");
  script_name("Debian LTS: Security Advisory for libdbi-perl (DLA-3035-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/05/msg00046.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3035-1");
  script_xref(name:"Advisory-ID", value:"DLA-3035-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/972180");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libdbi-perl'
  package(s) announced via the DLA-3035-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that CVE-2014-10401 was fixed incompletely in the
Perl5 Database Interface (DBI). An attacker could trigger information
disclosure through a different vector.

CVE-2014-10401

DBD::File drivers can open files from folders other than those
specifically passed via the f_dir attribute.

CVE-2014-10402

DBD::File drivers can open files from folders other than those
specifically passed via the f_dir attribute in the data source
name (DSN). NOTE: this issue exists because of an incomplete fix
for CVE-2014-10401.");

  script_tag(name:"affected", value:"'libdbi-perl' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
1.636-1+deb9u2.

We recommend that you upgrade your libdbi-perl packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libdbi-perl", ver:"1.636-1+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
