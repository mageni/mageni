# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 3426-2 using nvtgen 1.0
# Script version: 2.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807312");
  script_version("2021-11-23T15:20:34+0000");
  script_cve_id("CVE-2015-8543");
  script_name("Debian Security Advisory DSA 3426-2 (ctdb - security update)");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2016-03-08 12:38:02 +0530 (Tue, 08 Mar 2016)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3426.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|7)");
  script_tag(name:"affected", value:"ctdb on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy), this problem has been fixed
in version 1.12+git20120201-5.

For the stable distribution (jessie), this problem has been fixed in
version 2.5.4+debian0-4+deb8u1.

We recommend that you upgrade your ctdb packages.");
  script_tag(name:"summary", value:"The update for linux issued as DSA-3426-1 and DSA-3434-1 to address
CVE-2015-8543

uncovered a bug in ctdb, a clustered database to store
temporary data, leading to broken clusters. Updated packages are now
available to address this problem.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"ctdb", ver:"2.5.4+debian0-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ctdb-dbg", ver:"2.5.4+debian0-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ctdb-pcp-pmda", ver:"2.5.4+debian0-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libctdb-dev", ver:"2.5.4+debian0-4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ctdb", ver:"1.12+git20120201-5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ctdb-dbg", ver:"1.12+git20120201-5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libctdb-dev", ver:"1.12+git20120201-5", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}