# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892386");
  script_version("2020-09-30T09:06:11+0000");
  script_cve_id("CVE-2019-20919", "CVE-2020-14392", "CVE-2020-14393");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-09-30 09:06:11 +0000 (Wed, 30 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-29 03:00:44 +0000 (Tue, 29 Sep 2020)");
  script_name("Debian LTS: Security Advisory for libdbi-perl (DLA-2386-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/09/msg00026.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2386-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libdbi-perl'
  package(s) announced via the DLA-2386-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the Perl5 Database
Interface (DBI). An attacker could trigger a denial-of-service (DoS)
and possibly execute arbitrary code.

CVE-2019-20919

The hv_fetch() documentation requires checking for NULL and the
code does that. But, shortly thereafter, it calls SvOK(profile),
causing a NULL pointer dereference.

CVE-2020-14392

An untrusted pointer dereference flaw was found in Perl-DBI. A
local attacker who is able to manipulate calls to
dbd_db_login6_sv() could cause memory corruption, affecting the
service's availability.

CVE-2020-14393

A buffer overflow on via an overlong DBD class name in
dbih_setup_handle function may lead to data be written past the
intended limit.");

  script_tag(name:"affected", value:"'libdbi-perl' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1.636-1+deb9u1.

We recommend that you upgrade your libdbi-perl packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libdbi-perl", ver:"1.636-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
