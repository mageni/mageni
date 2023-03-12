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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2014.0019");
  script_cve_id("CVE-2014-0067");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DLA-0019)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-0019");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2014/dla-0019");
  script_xref(name:"URL", value:"https://wiki.postgresql.org/wiki/Apt");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-8.4' package(s) announced via the DLA-0019 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New upstream minor release. Users should upgrade to this version at their next scheduled maintenance window.

Noteworthy change:

Secure Unix-domain sockets of temporary postmasters started during make check (Noah Misch)

Any local user able to access the socket file could connect as the server's bootstrap superuser, then proceed to execute arbitrary code as the operating-system user running the test, as we previously noted in CVE-2014-0067. This change defends against that risk by placing the server's socket in a temporary, mode 0700 subdirectory of /tmp.

8.4.22 marks the end of life of the PostgreSQL 8.4 branch. No further releases will be made by the PostgreSQL Global Development Group.

Users of PostgreSQL 8.4 should look into upgrading to a newer PostgreSQL release. Options are:

Upgrading to Debian 7 (Wheezy), providing postgresql-9.1.

The use of the apt.postgresql.org repository, providing packages for all active PostgreSQL branches (9.0 up to 9.4 at the time of writing).

See [link moved to references] for more information about the repository.

A helper script to activate the repository is provided in /usr/share/doc/postgresql-8.4/examples/apt.postgresql.org.sh.

An LTS version of 8.4 is in planning that will cover the lifetime of squeeze-lts. Updates will probably made on a best-effort basis. Users can take advantage of this, but should still consider upgrading to newer PostgreSQL versions over the next months.

For Debian 6 Squeeze, these issues have been fixed in postgresql-8.4 version 8.4.22-0+deb6u1");

  script_tag(name:"affected", value:"'postgresql-8.4' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libecpg-compat3", ver:"8.4.22-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecpg-dev", ver:"8.4.22-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecpg6", ver:"8.4.22-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpgtypes3", ver:"8.4.22-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpq-dev", ver:"8.4.22-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpq5", ver:"8.4.22-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-8.4", ver:"8.4.22-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-8.4", ver:"8.4.22-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client", ver:"8.4.22-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-contrib-8.4", ver:"8.4.22-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-contrib", ver:"8.4.22-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-doc-8.4", ver:"8.4.22-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-doc", ver:"8.4.22-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plperl-8.4", ver:"8.4.22-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plpython-8.4", ver:"8.4.22-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-pltcl-8.4", ver:"8.4.22-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-server-dev-8.4", ver:"8.4.22-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql", ver:"8.4.22-0+deb6u1", rls:"DEB6"))) {
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
