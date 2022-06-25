# OpenVAS Vulnerability Test
# $Id: deb_3261.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3261-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703261");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-3406", "CVE-2015-3407", "CVE-2015-3408", "CVE-2015-3409");
  script_name("Debian Security Advisory DSA 3261-1 (libmodule-signature-perl - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-05-15 00:00:00 +0200 (Fri, 15 May 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3261.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"libmodule-signature-perl on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 0.68-1+deb7u2.

For the stable distribution (jessie), these problems have been fixed in
version 0.73-1+deb8u1.

For the testing distribution (stretch), these problems have been fixed
in version 0.78-1.

For the unstable distribution (sid), these problems have been fixed in
version 0.78-1.

We recommend that you upgrade your libmodule-signature-perl packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities were
discovered in libmodule-signature-perl, a Perl module to manipulate CPAN
SIGNATURE files. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2015-3406
John Lightsey discovered that Module::Signature could parse the
unsigned portion of the SIGNATURE file as the signed portion due to
incorrect handling of PGP signature boundaries.

CVE-2015-3407
John Lightsey discovered that Module::Signature incorrectly handles
files that are not listed in the SIGNATURE file. This includes some
files in the t/ directory that would execute when tests are run.

CVE-2015-3408
John Lightsey discovered that Module::Signature uses two argument
open() calls to read the files when generating checksums from the
signed manifest. This allows to embed arbitrary shell commands into
the SIGNATURE file that would execute during the signature
verification process.

CVE-2015-3409
John Lightsey discovered that Module::Signature incorrectly handles
module loading, allowing to load modules from relative paths in
@INC. A remote attacker providing a malicious module could use this
issue to execute arbitrary code during signature verification.

Note that libtest-signature-perl received an update for compatibility
with the fix for CVE-2015-3407

in libmodule-signature-perl.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libmodule-signature-perl", ver:"0.68-1+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}