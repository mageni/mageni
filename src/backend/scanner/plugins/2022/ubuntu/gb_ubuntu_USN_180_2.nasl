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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2005.180.2");
  script_cve_id("CVE-2005-2558");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-180-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU5\.10");

  script_xref(name:"Advisory-ID", value:"USN-180-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-180-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-dfsg-4.1' package(s) announced via the USN-180-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-180-1 fixed a vulnerability in the mysql-server package (which
ships version 4.0). Version 4.1 is vulnerable against the same flaw.

Please note that this package is not officially supported in Ubuntu
5.10.

Original advisory:

 'AppSecInc Team SHATTER discovered a buffer overflow in the 'CREATE
 FUNCTION' statement. By specifying a specially crafted long function
 name, a local or remote attacker with function creation privileges
 could crash the server or execute arbitrary code with server
 privileges.

 However, the right to create function is usually not granted to
 untrusted users.'");

  script_tag(name:"affected", value:"'mysql-dfsg-4.1' package(s) on Ubuntu 5.10.");

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

if(release == "UBUNTU5.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient14-dev", ver:"4.1.12-1ubuntu3.1", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient14", ver:"4.1.12-1ubuntu3.1", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-client-4.1", ver:"4.1.12-1ubuntu3.1", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-common-4.1", ver:"4.1.12-1ubuntu3.1", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-4.1", ver:"4.1.12-1ubuntu3.1", rls:"UBUNTU5.10"))) {
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
