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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.432");
  script_cve_id("CVE-2016-0773");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-09 02:29:00 +0000 (Sat, 09 Dec 2017)");

  script_name("Debian: Security Advisory (DLA-432)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-432");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-432");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-8.4' package(s) announced via the DLA-432 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several bugs were discovered in PostgreSQL, a relational database server system. The 8.4 branch is EOLed upstream, but still present in Debian squeeze. This new LTS minor version contains fixes that were applied upstream to the 9.1.20 version, backported to 8.4.22 which was the last version officially released by the PostgreSQL developers. This LTS effort for squeeze-lts is a community project sponsored by credativ GmbH.

This release is the last LTS update for PostgreSQL 8.4. Users should migrate to a newer PostgreSQL at the earliest opportunity.

Migration to Version 8.4.22lts6

A dump/restore is not required for those running 8.4.X. However, if you are upgrading from a version earlier than 8.4.22, see the relevant release notes.

Fixes

Fix infinite loops and buffer-overrun problems in regular expressions (Tom Lane) Very large character ranges in bracket expressions could cause infinite loops in some cases, and memory overwrites in other cases. (CVE-2016-0773)

Perform an immediate shutdown if the postmaster.pid file is removed (Tom Lane) The postmaster now checks every minute or so that postmaster.pid is still there and still contains its own PID. If not, it performs an immediate shutdown, as though it had received SIGQUIT. The main motivation for this change is to ensure that failed buildfarm runs will get cleaned up without manual intervention, but it also serves to limit the bad effects if a DBA forcibly removes postmaster.pid and then starts a new postmaster.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libecpg-compat3", ver:"8.4.22lts6-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecpg-dev", ver:"8.4.22lts6-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecpg6", ver:"8.4.22lts6-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpgtypes3", ver:"8.4.22lts6-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpq-dev", ver:"8.4.22lts6-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpq5", ver:"8.4.22lts6-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-8.4", ver:"8.4.22lts6-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-8.4", ver:"8.4.22lts6-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client", ver:"8.4.22lts6-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-contrib-8.4", ver:"8.4.22lts6-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-contrib", ver:"8.4.22lts6-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-doc-8.4", ver:"8.4.22lts6-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-doc", ver:"8.4.22lts6-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plperl-8.4", ver:"8.4.22lts6-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plpython-8.4", ver:"8.4.22lts6-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-pltcl-8.4", ver:"8.4.22lts6-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-server-dev-8.4", ver:"8.4.22lts6-0+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql", ver:"8.4.22lts6-0+deb6u1", rls:"DEB6"))) {
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
