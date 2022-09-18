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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2009.810.3");
  script_cve_id("CVE-2009-2404", "CVE-2009-2408", "CVE-2009-2409");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-16T08:45:11+0000");
  script_tag(name:"last_modification", value:"2022-09-16 08:45:11 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-810-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(8\.04\ LTS|8\.10|9\.04)");

  script_xref(name:"Advisory-ID", value:"USN-810-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-810-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/409864");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nss' package(s) announced via the USN-810-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-810-1 fixed vulnerabilities in NSS. Jozsef Kadlecsik noticed that
the new libraries on amd64 did not correctly set stack memory flags,
and caused applications using NSS (e.g. Firefox) to have an executable
stack. This reduced the effectiveness of some defensive security
protections. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Moxie Marlinspike discovered that NSS did not properly handle regular
 expressions in certificate names. A remote attacker could create a
 specially crafted certificate to cause a denial of service (via application
 crash) or execute arbitrary code as the user invoking the program.
 (CVE-2009-2404)

 Moxie Marlinspike and Dan Kaminsky independently discovered that NSS did
 not properly handle certificates with NULL characters in the certificate
 name. An attacker could exploit this to perform a machine-in-the-middle attack
 to view sensitive information or alter encrypted communications.
 (CVE-2009-2408)

 Dan Kaminsky discovered NSS would still accept certificates with MD2 hash
 signatures. As a result, an attacker could potentially create a malicious
 trusted certificate to impersonate another site. (CVE-2009-2409)");

  script_tag(name:"affected", value:"'nss' package(s) on Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

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

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-1d", ver:"3.12.3.1-0ubuntu0.8.04.2", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-1d", ver:"3.12.3.1-0ubuntu0.8.10.2", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-1d", ver:"3.12.3.1-0ubuntu0.9.04.2", rls:"UBUNTU9.04"))) {
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
