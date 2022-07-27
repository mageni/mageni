# OpenVAS Vulnerability Test
# $Id: deb_2234_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2234-1 (zodb)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.69732");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0668", "CVE-2009-0669");
  script_name("Debian Security Advisory DSA 2234-1 (zodb)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202234-1");
  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in python-zodb, a set of
tools for using ZODB, that could lead to arbitrary code execution in the worst
case. The Common Vulnerabilities and Exposures project identified the following
problems:

CVE-2009-0668

The ZEO server doesn't restrict the callables when unpickling data
received from a malicious client which can be used by an attacker to execute
arbitrary python code on the server by sending certain exception pickles. This
also allows an attacker to import any importable module as ZEO is importing the
module containing a callable specified in a pickle to test for a certain flag.

CVE-2009-0669

Due to a programming error an authorization method in the StorageServer
component of ZEO was not used as an internal method. This allows a malicious
client to bypass authentication when connecting to a ZEO server by simply
calling this authorization method.

The update also limits the number of new object ids a client can request
to 100 as it would be possible to consume huge amounts of resources by
requesting a big batch of new object ids. No CVE id has been assigned to this.

For the oldstable distribution (lenny), this problem has been fixed in
version 1:3.6.0-2+lenny3.

The stable distribution (squeeze) is not affected, it was fixed before
the initial release.

For the unstable distribution (sid), this problem has been fixed in
version 1:3.8.2-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your zodb packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to zodb
announced via advisory DSA 2234-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"4-zodb", ver:"1:3.6.0-2+lenny3", rls:"DEB5")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}