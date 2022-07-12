###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_phpmyadmin11.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 7e4e5c53-a56c-11e0-b180-00216aa06fc2
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
  script_oid("1.3.6.1.4.1.25623.1.0.69995");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-2505", "CVE-2011-2506", "CVE-2011-2507", "CVE-2011-2508");
  script_name("FreeBSD Ports: phpmyadmin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: phpmyadmin

CVE-2011-2505
libraries/auth/swekey/swekey.auth.lib.php in the Swekey authentication
feature in phpMyAdmin 3.x before 3.3.10.2 and 3.4.x before 3.4.3.1
assigns values to arbitrary parameters referenced in the query string,
which allows remote attackers to modify the SESSION superglobal array
via a crafted request, related to a 'remote variable manipulation
vulnerability.'

CVE-2011-2506
setup/lib/ConfigGenerator.class.php in phpMyAdmin 3.x before 3.3.10.2
and 3.4.x before 3.4.3.1 does not properly restrict the presence of
comment closing delimiters, which allows remote attackers to conduct
static code injection attacks by leveraging the ability to modify the
SESSION superglobal array.

CVE-2011-2507
libraries/server_synchronize.lib.php in the Synchronize implementation
in phpMyAdmin 3.x before 3.3.10.2 and 3.4.x before 3.4.3.1 does not
properly quote regular expressions, which allows remote authenticated
users to inject a PCRE e (aka PREG_REPLACE_EVAL) modifier, and
consequently execute arbitrary PHP code, by leveraging the ability to
modify the SESSION superglobal array.

CVE-2011-2508
Directory traversal vulnerability in libraries/display_tbl.lib.php in
phpMyAdmin 3.x before 3.3.10.2 and 3.4.x before 3.4.3.1, when a
certain MIME transformation feature is enabled, allows remote
authenticated users to include and execute arbitrary local files via a
.. (dot dot) in a GLOBALS[mime_map][$meta->name][transformation]
parameter.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-5.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-6.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-7.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-8.php");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/7e4e5c53-a56c-11e0-b180-00216aa06fc2.html");

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

bver = portver(pkg:"phpmyadmin");
if(!isnull(bver) && revcomp(a:bver, b:"3.4.3.1")<0) {
  txt += 'Package phpmyadmin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}