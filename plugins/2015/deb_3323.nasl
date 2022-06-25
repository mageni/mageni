# OpenVAS Vulnerability Test
# $Id: deb_3323.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3323-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703323");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2014-6585", "CVE-2014-8146", "CVE-2014-8147", "CVE-2015-4760");
  script_name("Debian Security Advisory DSA 3323-1 (icu - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-08-01 00:00:00 +0200 (Sat, 01 Aug 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3323.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"icu on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 4.8.1.1-12+deb7u3.

For the stable distribution (jessie), these problems have been fixed in
version 52.1-8+deb8u2.

For the testing distribution (stretch), these problems have been fixed
in version 52.1-10.

For the unstable distribution (sid), these problems have been fixed in
version 52.1-10.

We recommend that you upgrade your icu packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered
in the International Components for Unicode (ICU) library.

CVE-2014-8146
The Unicode Bidirectional Algorithm implementation does not properly
track directionally isolated pieces of text, which allows remote
attackers to cause a denial of service (heap-based buffer overflow)
or possibly execute arbitrary code via crafted text.

CVE-2014-8147
The Unicode Bidirectional Algorithm implementation uses an integer
data type that is inconsistent with a header file, which allows
remote attackers to cause a denial of service (incorrect malloc
followed by invalid free) or possibly execute arbitrary code via
crafted text.

CVE-2015-4760
The Layout Engine was missing multiple boundary checks. These could
lead to buffer overflows and memory corruption. A specially crafted
file could cause an application using ICU to parse untrusted font
files to crash and, possibly, execute arbitrary code.

Additionally, it was discovered that the patch applied to ICU in DSA-3187-1
for CVE-2014-6585
was incomplete, possibly leading to an invalid memory
access. This could allow remote attackers to disclose portion of private
memory via crafted font files.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"icu-doc", ver:"4.8.1.1-12+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libicu-dev", ver:"4.8.1.1-12+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libicu48:amd64", ver:"4.8.1.1-12+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libicu48:i386", ver:"4.8.1.1-12+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libicu48-dbg", ver:"4.8.1.1-12+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}