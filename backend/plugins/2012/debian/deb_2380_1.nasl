# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory DSA 2380-1 (foomatic-filters)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.70699");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-2697", "CVE-2011-2964");
  script_version("2021-11-23T15:20:34+0000");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2012-02-11 03:26:17 -0500 (Sat, 11 Feb 2012)");
  script_name("Debian Security Advisory DSA 2380-1 (foomatic-filters)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(5|6|7)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202380-1");
  script_tag(name:"insight", value:"It was discovered that the foomatic-filters, a support package for
setting up printers, allowed authenticated users to submit crafted
print jobs which would execute shell commands on the print servers.

CVE-2011-2697 was assigned to the vulnerability in the Perl
implementation included in lenny, and CVE-2011-2964 to the
vulnerability affecting the C reimplementation part of squeeze.

For the oldstable distribution (lenny), this problem has been fixed in
version 3.0.2-20080211-3.2+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 4.0.5-6+squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 4.0.9-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your foomatic-filters packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to foomatic-filters
announced via advisory DSA 2380-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"foomatic-filters", ver:"3.0.2-20080211-3.2+lenny1", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"foomatic-filters", ver:"4.0.5-6+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"foomatic-filters", ver:"4.0.9-1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}