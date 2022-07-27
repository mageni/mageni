# OpenVAS Vulnerability Test
# $Id: deb_2506_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2506-1 (libapache-mod-security)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.71485");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2012-2751");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-08-10 03:07:44 -0400 (Fri, 10 Aug 2012)");
  script_name("Debian Security Advisory DSA 2506-1 (libapache-mod-security)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202506-1");
  script_tag(name:"insight", value:"Qualys Vulnerability & Malware Research Labs discovered a vulnerability in
ModSecurity, a security module for the Apache webserver. In situations where
both 'Content:Disposition: attachment' and 'Content-Type: multipart' were
present in HTTP headers, the vulernability could allow an attacker to bypass
policy and execute cross-site script (XSS) attacks through properly crafted
HTML documents.

For the stable distribution (squeeze), this problem has been fixed in
version 2.5.12-1+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 2.6.6-1.

For the unstable distribution (sid), this problem has been fixed in
version 2.6.6-1.

In testing and unstable distribution, the source package has been renamed to
modsecurity-apache.");

  script_tag(name:"solution", value:"We recommend that you upgrade your libapache-mod-security packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to libapache-mod-security
announced via advisory DSA 2506-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libapache-mod-security", ver:"2.5.12-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mod-security-common", ver:"2.5.12-1+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}