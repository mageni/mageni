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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.447");
  script_cve_id("CVE-2016-0640", "CVE-2016-0641", "CVE-2016-0642", "CVE-2016-0643", "CVE-2016-0644", "CVE-2016-0646", "CVE-2016-0647", "CVE-2016-0648", "CVE-2016-0649", "CVE-2016-0650", "CVE-2016-0666", "CVE-2016-2047");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Debian: Security Advisory (DLA-447)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-447");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-447");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-49.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2016-2881694.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-5.5' package(s) announced via the DLA-447 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovereded in the MySQL database server, which are fixed in the new upstream version 5.5.49. Please see the MySQL 5.5 Release Notes and Oracle's Critical Patch Update advisory for further details:


[link moved to references]

[link moved to references]

For Debian 7 Wheezy, these issues have been fixed in mysql-5.5 version 5.5.49-0+deb7u1. We recommend you to upgrade your mysql-5.5 packages.");

  script_tag(name:"affected", value:"'mysql-5.5' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient-dev", ver:"5.5.49-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient18", ver:"5.5.49-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqld-dev", ver:"5.5.49-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqld-pic", ver:"5.5.49-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client-5.5", ver:"5.5.49-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client", ver:"5.5.49-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-common", ver:"5.5.49-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.5", ver:"5.5.49-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-core-5.5", ver:"5.5.49-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server", ver:"5.5.49-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-source-5.5", ver:"5.5.49-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-testsuite-5.5", ver:"5.5.49-0+deb7u1", rls:"DEB7"))) {
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
