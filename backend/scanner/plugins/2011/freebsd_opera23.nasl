###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_opera23.nasl 14170 2019-03-14 09:24:12Z cfischer $
#
# Auto generated from VID 2eda0c54-34ab-11e0-8103-00215c6a37bb
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68952");
  script_version("$Revision: 14170 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 10:24:12 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-03-05 22:25:39 +0100 (Sat, 05 Mar 2011)");
  script_cve_id("CVE-2011-0450", "CVE-2011-0681", "CVE-2011-0682", "CVE-2011-0683", "CVE-2011-0684", "CVE-2011-0685", "CVE-2011-0686", "CVE-2011-0687");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: opera, opera-devel, linux-opera");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  opera
   opera-devel
   linux-opera

CVE-2011-0450
The downloads manager in Opera before 11.01 on Windows does not
properly determine the pathname of the filesystem-viewing application,
which allows user-assisted remote attackers to execute arbitrary code
via a crafted web site that hosts an executable file.

CVE-2011-0681
The Cascading Style Sheets (CSS) Extensions for XML implementation in
Opera before 11.01 recognizes links to javascript: URLs in the -o-link
property, which makes it easier for remote attackers to bypass CSS
filtering via a crafted URL.

CVE-2011-0682
Integer truncation error in opera.dll in Opera before 11.01 allows
remote attackers to execute arbitrary code or cause a denial of
service (memory corruption) via an HTML form with a select element
that contains a large number of children.

CVE-2011-0683
Opera before 11.01 does not properly restrict the use of opera: URLs,
which makes it easier for remote attackers to conduct clickjacking
attacks via a crafted web site.

CVE-2011-0684
Opera before 11.01 does not properly handle redirections and
unspecified other HTTP responses, which allows remote web servers to
obtain sufficient access to local files to use these files as page
resources, and consequently obtain potentially sensitive information
from the contents of the files, via an unknown response manipulation.

CVE-2011-0685
The Delete Private Data feature in Opera before 11.01 does not
properly implement the 'Clear all email account passwords' option,
which might allow physically proximate attackers to access an e-mail
account via an unattended workstation.

CVE-2011-0686
Unspecified vulnerability in Opera before 11.01 allows remote
attackers to cause a denial of service (application crash) via unknown
content on a web page, as demonstrated by vkontakte.ru.

CVE-2011-0687
Opera before 11.01 does not properly implement Wireless Application
Protocol (WAP) dropdown lists, which allows user-assisted remote
attackers to cause a denial of service (application crash) via a
crafted WAP document.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/982/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/983/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/984/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43023");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/2eda0c54-34ab-11e0-8103-00215c6a37bb.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"opera");
if(!isnull(bver) && revcomp(a:bver, b:"11.01")<0) {
  txt += 'Package opera version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"opera-devel");
if(!isnull(bver) && revcomp(a:bver, b:"11.01")<0) {
  txt += 'Package opera-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-opera");
if(!isnull(bver) && revcomp(a:bver, b:"11.01")<0) {
  txt += 'Package linux-opera version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}