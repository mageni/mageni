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
  script_oid("1.3.6.1.4.1.25623.1.0.705364");
  script_cve_id("CVE-2022-25147");
  script_tag(name:"creation_date", value:"2023-02-28 02:00:08 +0000 (Tue, 28 Feb 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-07 21:46:00 +0000 (Tue, 07 Feb 2023)");

  script_name("Debian: Security Advisory (DSA-5364)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5364");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5364");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/apr-util");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apr-util' package(s) announced via the DSA-5364 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ronald Crane discovered that missing input sanitizing in the apr_base64 functions of apr-util, the Apache Portable Runtime utility library, may result in denial of service or potentially the execution of arbitrary code.

For the stable distribution (bullseye), this problem has been fixed in version 1.6.1-5+deb11u1.

We recommend that you upgrade your apr-util packages.

For the detailed security status of apr-util please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'apr-util' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1-dbd-mysql", ver:"1.6.1-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1-dbd-odbc", ver:"1.6.1-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1-dbd-pgsql", ver:"1.6.1-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1-dbd-sqlite3", ver:"1.6.1-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1-dev", ver:"1.6.1-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1-ldap", ver:"1.6.1-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaprutil1", ver:"1.6.1-5+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
