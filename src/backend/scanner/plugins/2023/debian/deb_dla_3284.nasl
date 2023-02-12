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
  script_oid("1.3.6.1.4.1.25623.1.0.893284");
  script_version("2023-01-30T10:09:19+0000");
  script_cve_id("CVE-2020-16093", "CVE-2020-36658");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-30 10:09:19 +0000 (Mon, 30 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-29 02:00:06 +0000 (Sun, 29 Jan 2023)");
  script_name("Debian LTS: Security Advisory for libapache-session-ldap-perl (DLA-3284-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00024.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3284-1");
  script_xref(name:"Advisory-ID", value:"DLA-3284-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libapache-session-ldap-perl'
  package(s) announced via the DLA-3284-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Apache::Session::LDAP before 0.5, validity of the X.509 certificate
is not checked by default when connecting to remote LDAP backends,
because the default configuration of the Net::LDAPS module for Perl is
used.

This update changes the default behavior to require X.509 validation
against the distribution bundle /etc/ssl/certs/ca-certificates.crt.
Previous behavior can reverted by setting `ldapVerify => 'none'` when
initializing the Apache::Session::LDAP object.

NOTE: this update is a prerequisite for LemonLDAP::NG's CVE-2020-16093
fix when its session backend is set to Apache::Session::LDAP.");

  script_tag(name:"affected", value:"'libapache-session-ldap-perl' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, this problem has been fixed in version
0.4-1+deb10u1.

We recommend that you upgrade your libapache-session-ldap-perl packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libapache-session-ldap-perl", ver:"0.4-1+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
