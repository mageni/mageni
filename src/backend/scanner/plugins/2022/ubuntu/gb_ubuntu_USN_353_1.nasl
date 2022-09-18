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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.353.1");
  script_cve_id("CVE-2006-2937", "CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-353-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(5\.04|5\.10|6\.06\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-353-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-353-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-353-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dr. Henson of the OpenSSL core team and Open Network Security
discovered a mishandled error condition in the ASN.1 parser. By
sending specially crafted packet data, a remote attacker could exploit
this to trigger an infinite loop, which would render the service
unusable and consume all available system memory. (CVE-2006-2937)

Certain types of public key could take disproportionate amounts of
time to process. The library now limits the maximum key exponent size
to avoid Denial of Service attacks. (CVE-2006-2940)

Tavis Ormandy and Will Drewry of the Google Security Team discovered a
buffer overflow in the SSL_get_shared_ciphers() function. By sending
specially crafted packets to applications that use this function (like
Exim, MySQL, or the openssl command line tool), a remote attacker
could exploit this to execute arbitrary code with the server's
privileges. (CVE-2006-3738)

Tavis Ormandy and Will Drewry of the Google Security Team reported
that the get_server_hello() function did not sufficiently check the
client's session certificate. This could be exploited to crash clients
by remote attackers sending specially crafted SSL responses.
(CVE-2006-4343)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 5.04, Ubuntu 5.10, Ubuntu 6.06.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libssl0.9.7", ver:"0.9.7e-3ubuntu0.4", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU5.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl0.9.7", ver:"0.9.7g-1ubuntu1.3", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8a-7ubuntu0.2", rls:"UBUNTU6.06 LTS"))) {
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
