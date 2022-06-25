# OpenVAS Vulnerability Test
# $Id: deb_3091.nasl 14277 2019-03-18 14:45:38Z cfischer $
# Auto-generated from advisory DSA 3091-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703091");
  script_version("$Revision: 14277 $");
  script_cve_id("CVE-2014-7273", "CVE-2014-7274", "CVE-2014-7275");
  script_name("Debian Security Advisory DSA 3091-1 (getmail4 - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-12-07 00:00:00 +0100 (Sun, 07 Dec 2014)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-3091.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"getmail4 on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
these problems have been fixed in version 4.46.0-1~deb7u1.

For the upcoming stable distribution (jessie), these problems have been
fixed in version 4.46.0-1.

For the unstable distribution (sid), these problems have been fixed in
version 4.46.0-1.

We recommend that you upgrade your getmail4 packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been
discovered in getmail4, a mail retriever with support for POP3, IMAP4 and SDPS,
that could allow man-in-the-middle attacks.

CVE-2014-7273
The IMAP-over-SSL implementation in getmail 4.0.0 through 4.43.0
does not verify X.509 certificates from SSL servers, which allows
man-in-the-middle attackers to spoof IMAP servers and obtain
sensitive information via a crafted certificate.

CVE-2014-7274
The IMAP-over-SSL implementation in getmail 4.44.0 does not verify
that the server hostname matches a domain name in the subject's
Common Name (CN) field of the X.509 certificate, which allows
man-in-the-middle attackers to spoof IMAP servers and obtain
sensitive information via a crafted certificate from a recognized
Certification Authority.

CVE-2014-7275
The POP3-over-SSL implementation in getmail 4.0.0 through 4.44.0
does not verify X.509 certificates from SSL servers, which allows
man-in-the-middle attackers to spoof POP3 servers and obtain
sensitive information via a crafted certificate.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"getmail4", ver:"4.46.0-1~deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}