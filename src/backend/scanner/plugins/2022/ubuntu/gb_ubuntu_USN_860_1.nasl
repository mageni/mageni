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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2009.860.1");
  script_cve_id("CVE-2009-3094", "CVE-2009-3095", "CVE-2009-3555");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-860-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|8\.04\ LTS|8\.10|9\.04|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-860-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-860-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-860-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marsh Ray and Steve Dispensa discovered a flaw in the TLS and SSLv3
protocols. If an attacker could perform a machine-in-the-middle attack at the
start of a TLS connection, the attacker could inject arbitrary content at
the beginning of the user's session. The flaw is with TLS renegotiation and
potentially affects any software that supports this feature. Attacks
against the HTTPS protocol are known, with the severity of the issue
depending on the safeguards used in the web application. Until the TLS
protocol and underlying libraries are adjusted to defend against this
vulnerability, a partial, temporary workaround has been applied to Apache
that disables client initiated TLS renegotiation. This update does not
protect against server initiated TLS renegotiation when using
SSLVerifyClient and SSLCipherSuite on a per Directory or Location basis.
Users can defend against server inititiated TLS renegotiation attacks by
adjusting their Apache configuration to use SSLVerifyClient and
SSLCipherSuite only on the server or virtual host level. (CVE-2009-3555)

It was discovered that mod_proxy_ftp in Apache did not properly sanitize
its input when processing replies to EPASV and PASV commands. An attacker
could use this to cause a denial of service in the Apache child process.
(CVE-2009-3094)

Another flaw was discovered in mod_proxy_ftp. If Apache is configured as a
reverse proxy, an attacker could send a crafted HTTP header to bypass
intended access controls and send arbitrary commands to the FTP server.
(CVE-2009-3095)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2-common", ver:"2.0.55-4ubuntu2.9", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.8-1ubuntu0.14", rls:"UBUNTU8.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.9-7ubuntu3.5", rls:"UBUNTU8.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.11-2ubuntu2.5", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.12-1ubuntu2.1", rls:"UBUNTU9.10"))) {
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
