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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2005.174.1");
  script_cve_id("CVE-2005-2151");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-174-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU5\.04");

  script_xref(name:"Advisory-ID", value:"USN-174-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-174-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'courier' package(s) announced via the USN-174-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A Denial of Service vulnerability has been discovered in the Courier
mail server. Due to a flawed status code check, failed DNS (domain
name service) queries for SPF (sender policy framework) were not
handled properly and could lead to memory corruption. A malicious DNS
server could exploit this to crash the Courier server.

However, SPF is not enabled by default, so you are only vulnerable if
you explicitly enabled it.

The Ubuntu 4.10 version of courier is not affected by this.");

  script_tag(name:"affected", value:"'courier' package(s) on Ubuntu 5.04.");

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

if(release == "UBUNTU5.04") {

  if(!isnull(res = isdpkgvuln(pkg:"courier-authdaemon", ver:"0.47-3ubuntu1.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-authmysql", ver:"0.47-3ubuntu1.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-authpostgresql", ver:"0.47-3ubuntu1.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-base", ver:"0.47-3ubuntu1.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-doc", ver:"0.47-3ubuntu1.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-faxmail", ver:"0.47-3ubuntu1.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-imap-ssl", ver:"3.0.8-3ubuntu1.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-imap", ver:"3.0.8-3ubuntu1.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-ldap", ver:"0.47-3ubuntu1.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-maildrop", ver:"0.47-3ubuntu1.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-mlm", ver:"0.47-3ubuntu1.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-mta-ssl", ver:"0.47-3ubuntu1.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-mta", ver:"0.47-3ubuntu1.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-pcp", ver:"0.47-3ubuntu1.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-pop-ssl", ver:"0.47-3ubuntu1.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-pop", ver:"0.47-3ubuntu1.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-ssl", ver:"0.47-3ubuntu1.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-webadmin", ver:"0.47-3ubuntu1.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sqwebmail", ver:"0.47-3ubuntu1.1", rls:"UBUNTU5.04"))) {
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
