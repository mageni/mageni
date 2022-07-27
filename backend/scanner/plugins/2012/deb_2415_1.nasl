# OpenVAS Vulnerability Test
# $Id: deb_2415_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2415-1 (libmodplug)
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
  script_oid("1.3.6.1.4.1.25623.1.0.71142");
  script_cve_id("CVE-2011-1761", "CVE-2011-2911", "CVE-2011-2912", "CVE-2011-2913", "CVE-2011-2914", "CVE-2011-2915");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-03-12 11:31:30 -0400 (Mon, 12 Mar 2012)");
  script_name("Debian Security Advisory DSA 2415-1 (libmodplug)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202415-1");
  script_tag(name:"insight", value:"Several vulnerabilities that can lead to the execution of arbitrary code
have been discovered in libmodplug, a library for mod music based on
ModPlug.  The Common Vulnerabilities and Exposures project identifies
the following issues:

CVE-2011-1761

epiphant discovered that the abc file parser is vulnerable to several
stack-based buffer overflows that potentially lead to the execution
of arbitrary code.

CVE-2011-2911

Hossein Lotfi of Secunia discovered that the CSoundFile::ReadWav
function is vulnerable to an integer overflow which leads to a
heap-based buffer overflow.  An attacker can exploit this flaw to
potentially execute arbitrary code by tricking a victim into opening
crafted WAV files.

CVE-2011-2912

Hossein Lotfi of Secunia discovered that the CSoundFile::ReadS3M
function is vulnerable to a stack-based buffer overflow.  An attacker
can exploit this flaw to potentially execute arbitrary code by
tricking a victim into opening crafted S3M files.

CVE-2011-2913

Hossein Lotfi of Secunia discovered that the CSoundFile::ReadAMS
function suffers from an off-by-one vulnerability that leads to
memory corruption.  An attacker can exploit this flaw to potentially
execute arbitrary code by tricking a victim into opening crafted AMS
files.

CVE-2011-2914

It was discovered that the CSoundFile::ReadDSM function suffers
from an off-by-one vulnerability that leads to memory corruption.
An attacker can exploit this flaw to potentially execute arbitrary
code by tricking a victim into opening crafted DSM files.

CVE-2011-2915

It was discovered that the CSoundFile::ReadAMS2 function suffers
from an off-by-one vulnerability that leads to memory corruption.
An attacker can exploit this flaw to potentially execute arbitrary
code by tricking a victim into opening crafted AMS files.


For the stable distribution (squeeze), this problem has been fixed in
version 1:0.8.8.1-1+squeeze2.

For the testing (wheezy) and unstable (sid) distributions, this problem
has been fixed in version 1:0.8.8.4-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your libmodplug packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to libmodplug
announced via advisory DSA 2415-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libmodplug-dev", ver:"1:0.8.8.1-1+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmodplug1", ver:"1:0.8.8.1-1+squeeze2", rls:"DEB6")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}