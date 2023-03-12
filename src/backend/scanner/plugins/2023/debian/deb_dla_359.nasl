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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.359");
  script_cve_id("CVE-2015-0499", "CVE-2015-0501", "CVE-2015-0505", "CVE-2015-2568", "CVE-2015-2571", "CVE-2015-2573", "CVE-2015-2582", "CVE-2015-2620", "CVE-2015-2643", "CVE-2015-2648", "CVE-2015-4737", "CVE-2015-4752", "CVE-2015-4792", "CVE-2015-4802", "CVE-2015-4815", "CVE-2015-4816", "CVE-2015-4819", "CVE-2015-4826", "CVE-2015-4830", "CVE-2015-4836", "CVE-2015-4858", "CVE-2015-4861", "CVE-2015-4870", "CVE-2015-4879", "CVE-2015-4913");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DLA-359)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-359");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-359");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-5.5' package(s) announced via the DLA-359 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Oracle, the upstream maintainer of MySQL, no longer supports MySQL version 5.1, which is included in Debian 6.0 squeeze. MySQL 5.1 likely suffers from multiple vulnerabilities fixed in newer versions after the end of upstream support, but Oracle does not disclose enough information either to verify or to fix them.

As an alternative, the Debian LTS team is providing MySQL 5.5 packages for use in Debian 6.0 squeeze. We recommend that Squeeze LTS users install them and migrate their MySQL databases.

Please note that a dist-upgrade will not consider these MySQL 5.5 packages automatically, so users need to install them explicitly.

If you are running a MySQL server:

apt-get install mysql-server-5.5

If you only need the MySQL client:

apt-get install mysql-client-5.5

Compatibility updates

Some packages were updated to solve incompatibility issues, that were fixed in the following versions:

bacula-director-mysql 5.0.2-2.2+squeeze2

cacti 0.8.7g-1+squeeze9

phpmyadmin 4:3.3.7-10

postfix-policyd 1.82-2+deb6u1

prelude-manager 1.0.0-1+deb6u1

We recommend that you upgrade these packages before upgrading to MySQL 5.5. A common dist-upgrade should be enough.

We have done our best to provide you with reliable MySQL 5.5 packages. We have made available test packages for some time, although we did not get any feedback from users. In any case, don't hesitate to report any issues related to this MySQL upgrade to debian-lts@lists.debian.org.");

  script_tag(name:"affected", value:"'mysql-5.5' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient18", ver:"5.5.46-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client-5.5", ver:"5.5.46-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client", ver:"5.5.46-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-common-5.5", ver:"5.5.46-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.5", ver:"5.5.46-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-core-5.5", ver:"5.5.46-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server", ver:"5.5.46-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-source-5.5", ver:"5.5.46-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-testsuite-5.5", ver:"5.5.46-0+deb6u1", rls:"DEB6"))) {
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
