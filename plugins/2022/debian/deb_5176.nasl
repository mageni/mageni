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
  script_oid("1.3.6.1.4.1.25623.1.0.705176");
  script_version("2022-07-08T06:04:19+0000");
  script_cve_id("CVE-2022-0544", "CVE-2022-0545", "CVE-2022-0546");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-07-08 06:04:19 +0000 (Fri, 08 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-04 20:34:00 +0000 (Fri, 04 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-07-06 01:00:19 +0000 (Wed, 06 Jul 2022)");
  script_name("Debian: Security Advisory for blender (DSA-5176-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|10)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5176.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5176-1");
  script_xref(name:"Advisory-ID", value:"DSA-5176-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'blender'
  package(s) announced via the DSA-5176-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in various image parsers in
Blender, a 3D modeller/ renderer, which may result in denial of service
or the execution of arbitrary code if a malformed file is opened.");

  script_tag(name:"affected", value:"'blender' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (buster), these problems have been fixed
in version 2.79.b+dfsg0-7+deb10u1.

For the stable distribution (bullseye), these problems have been fixed in
version 2.83.5+dfsg-5+deb11u1.

We recommend that you upgrade your blender packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"blender", ver:"2.83.5+dfsg-5+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"blender-data", ver:"2.83.5+dfsg-5+deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"blender", ver:"2.79.b+dfsg0-7+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"blender-data", ver:"2.79.b+dfsg0-7+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
