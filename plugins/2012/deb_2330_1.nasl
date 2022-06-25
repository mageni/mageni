# OpenVAS Vulnerability Test
# $Id: deb_2330_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2330-1 (simplesamlphp)
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
  script_oid("1.3.6.1.4.1.25623.1.0.70545");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-11 02:26:59 -0500 (Sat, 11 Feb 2012)");
  script_name("Debian Security Advisory DSA 2330-1 (simplesamlphp)");
  script_cve_id("CVE-2011-4625");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202330-1");
  script_tag(name:"insight", value:"Issues were found in the handling of XML encryption in simpleSAMLphp,
an application for federated authentication. The following two issues
have been addressed:

It may be possible to use an SP as an oracle to decrypt encrypted
messages sent to that SP.

It may be possible to use the SP as a key oracle which can be used
to forge messages from that SP by issuing 300000-2000000 queries to
the SP.

The oldstable distribution (lenny) does not contain simplesamlphp.

For the stable distribution (squeeze), this problem has been fixed in
version 1.6.3-2.

The testing distribution (wheezy) will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 1.8.2-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your simplesamlphp packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to simplesamlphp
announced via advisory DSA 2330-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"simplesamlphp", ver:"1.6.3-2", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}