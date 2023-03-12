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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2012.2301");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2301)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6)");

  script_xref(name:"Advisory-ID", value:"DSA-2301");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2301");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rails' package(s) announced via the DSA-2301 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Rails, the Ruby web application framework. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-4214

A cross-site scripting (XSS) vulnerability had been found in the strip_tags function. An attacker may inject non-printable characters that certain browsers will then evaluate. This vulnerability only affects the oldstable distribution (lenny).

CVE-2011-2930

A SQL injection vulnerability had been found in the quote_table_name method that could allow malicious users to inject arbitrary SQL into a query.

CVE-2011-2931

A cross-site scripting (XSS) vulnerability had been found in the strip_tags helper. An parsing error can be exploited by an attacker, who can confuse the parser and may inject HTML tags into the output document.

CVE-2011-3186

A newline (CRLF) injection vulnerability had been found in response.rb. This vulnerability allows an attacker to inject arbitrary HTTP headers and conduct HTTP response splitting attacks via the Content-Type header.

For the oldstable distribution (lenny), this problem has been fixed in version 2.1.0-7+lenny2.

For the stable distribution (squeeze), this problem has been fixed in version 2.3.5-1.2+squeeze2.

For the unstable distribution (sid), this problem has been fixed in version 2.3.14.

We recommend that you upgrade your rails packages.");

  script_tag(name:"affected", value:"'rails' package(s) on Debian 5, Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"rails", ver:"2.1.0-7+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libactionmailer-ruby1.8", ver:"2.3.5-1.2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libactionmailer-ruby", ver:"2.3.5-1.2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libactionpack-ruby1.8", ver:"2.3.5-1.2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libactionpack-ruby", ver:"2.3.5-1.2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libactiverecord-ruby1.8", ver:"2.3.5-1.2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libactiverecord-ruby1.9.1", ver:"2.3.5-1.2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libactiverecord-ruby", ver:"2.3.5-1.2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libactiveresource-ruby1.8", ver:"2.3.5-1.2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libactiveresource-ruby", ver:"2.3.5-1.2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libactivesupport-ruby1.8", ver:"2.3.5-1.2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libactivesupport-ruby1.9.1", ver:"2.3.5-1.2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libactivesupport-ruby", ver:"2.3.5-1.2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rails-doc", ver:"2.3.5-1.2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rails-ruby1.8", ver:"2.3.5-1.2+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rails", ver:"2.3.5-1.2+squeeze2", rls:"DEB6"))) {
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
