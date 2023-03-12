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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.491");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-491)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-491");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-491");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-9.1' package(s) announced via the DLA-491 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The PostgreSQL project released a new version of the PostgreSQL 9.1 branch:

Clear the OpenSSL error queue before OpenSSL calls, rather than assuming it's clear already, and make sure we leave it clear afterwards (Peter Geoghegan, Dave Vitek, Peter Eisentraut)

This change prevents problems when there are multiple connections using OpenSSL within a single process and not all the code involved follows the same rules for when to clear the error queue. Failures have been reported specifically when a client application uses SSL connections in libpq concurrently with SSL connections using the PHP, Python, or Ruby wrappers for OpenSSL. It's possible for similar problems to arise within the server as well, if an extension module establishes an outgoing SSL connection.

Fix 'failed to build any N-way joins' planner error with a full join enclosed in the right-hand side of a left join (Tom Lane)

Fix possible misbehavior of TH, th, and Y,YYY format codes in to_timestamp() (Tom Lane)

These could advance off the end of the input string, causing subsequent format codes to read garbage.

Fix dumping of rules and views in which the array argument of a value operator ANY (array) construct is a sub-SELECT (Tom Lane)

Make pg_regress use a startup timeout from the PGCTLTIMEOUT environment variable, if that's set (Tom Lane)

This is for consistency with a behavior recently added to pg_ctl, it eases automated testing on slow machines.

Fix pg_upgrade to correctly restore extension membership for operator families containing only one operator class (Tom Lane)

In such a case, the operator family was restored into the new database, but it was no longer marked as part of the extension. This had no immediate ill effects, but would cause later pg_dump runs to emit output that would cause (harmless) errors on restore.

Rename internal function strtoi() to strtoint() to avoid conflict with a NetBSD library function (Thomas Munro)

Use the FORMAT_MESSAGE_IGNORE_INSERTS flag where appropriate. No live bug is known to exist here, but it seems like a good idea to be careful.

For Debian 7 Wheezy, these problems have been fixed in version 9.1.22-0+deb7u1.

We recommend that you upgrade your postgresql-9.1 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'postgresql-9.1' package(s) on Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libecpg-compat3", ver:"9.1.22-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecpg-dev", ver:"9.1.22-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecpg6", ver:"9.1.22-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpgtypes3", ver:"9.1.22-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpq-dev", ver:"9.1.22-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpq5", ver:"9.1.22-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-9.1-dbg", ver:"9.1.22-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-9.1", ver:"9.1.22-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-9.1", ver:"9.1.22-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-contrib-9.1", ver:"9.1.22-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-doc-9.1", ver:"9.1.22-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plperl-9.1", ver:"9.1.22-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plpython-9.1", ver:"9.1.22-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plpython3-9.1", ver:"9.1.22-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-pltcl-9.1", ver:"9.1.22-0+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-server-dev-9.1", ver:"9.1.22-0+deb7u1", rls:"DEB7"))) {
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
