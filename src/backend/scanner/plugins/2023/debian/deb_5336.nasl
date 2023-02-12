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
  script_oid("1.3.6.1.4.1.25623.1.0.705336");
  script_version("2023-02-03T10:10:17+0000");
  script_cve_id("CVE-2022-47951");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-02-03 10:10:17 +0000 (Fri, 03 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-03 02:00:07 +0000 (Fri, 03 Feb 2023)");
  script_name("Debian: Security Advisory for glance (DSA-5336-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5336.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5336-1");
  script_xref(name:"Advisory-ID", value:"DSA-5336-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glance'
  package(s) announced via the DSA-5336-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Guillaume Espanel, Pierre Libeau, Arnaud Morin and Damien Rannou
discovered that missing input sanitising in the handling of VMDK images
in Glance, the OpenStack image registry and delivery service, may result
in information disclosure.");

  script_tag(name:"affected", value:"'glance' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), this problem has been fixed in
version 2:21.0.0-2+deb11u1.

We recommend that you upgrade your glance packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"glance", ver:"2:21.0.0-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"glance-api", ver:"2:21.0.0-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"glance-common", ver:"2:21.0.0-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"glance-doc", ver:"2:21.0.0-2+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-glance", ver:"2:21.0.0-2+deb11u1", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
