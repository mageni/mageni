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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.2089");
  script_cve_id("CVE-2010-1917", "CVE-2010-2225", "CVE-2010-3065");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2089)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2089");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2089");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-2089 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in PHP 5, an hypertext preprocessor. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-1917

The fnmatch function can be abused to conduct denial of service attacks (by crashing the interpreter) by the means of a stack overflow.

CVE-2010-2225

The SplObjectStorage unserializer allows attackers to execute arbitrary code via serialized data by the means of a use-after-free vulnerability.

CVE-2010-3065

The default sessions serializer does not correctly handle a special marker, which allows an attacker to inject arbitrary variables into the session and possibly exploit vulnerabilities in the unserializer.

CVE-2010-1128

For this vulnerability (predictable entropy for the Linear Congruential Generator used to generate session ids) we do not consider upstream's solution to be sufficient. It is recommended to uncomment the session.entropy_file and session.entropy_length settings in the php.ini files. Further improvements can be achieved by setting session.hash_function to 1 (one) and incrementing the value of session.entropy_length.

For the stable distribution (lenny), these problems have been fixed in version 5.2.6.dfsg.1-1+lenny9.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php5filter", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php-pear", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cgi", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-cli", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-common", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-curl", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-dbg", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-dev", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-gd", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-gmp", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-imap", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-interbase", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-ldap", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-mcrypt", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-mhash", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-mysql", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-odbc", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-pgsql", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-pspell", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-recode", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-snmp", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-sqlite", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-sybase", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-tidy", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-xmlrpc", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5-xsl", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php5", ver:"5.2.6.dfsg.1-1+lenny9", rls:"DEB5"))) {
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
