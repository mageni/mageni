###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_kdelibs5.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 6d21a287-fce0-11e0-a828-00235a5f2c9a
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.70615");
  script_tag(name:"creation_date", value:"2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_cve_id("CVE-2011-3365", "CVE-2011-3366");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 11762 $");
  script_name("FreeBSD Ports: kdelibs");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  kdelibs
   rekonq

CVE-2011-3365
The KDE SSL Wrapper (KSSL) API in KDE SC 4.6.0 through 4.7.1, and
possibly earlier versions, does not use a certain font when rendering
certificate fields in a security dialog, which allows remote attackers
to spoof the common name (CN) of a certificate via rich text.

CVE-2011-3366
Rekonq 0.7.0 and earlier does not use a certain font when rendering
certificate fields in a security dialog, which allows remote attackers
to spoof the common name (CN) of a certificate via rich text.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20111003-1.txt");
  script_xref(name:"URL", value:"http://www.nth-dimension.org.uk/pub/NDSA20111003.txt.asc");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/6d21a287-fce0-11e0-a828-00235a5f2c9a.html");

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

bver = portver(pkg:"kdelibs");
if(!isnull(bver) && revcomp(a:bver, b:"4.0")>=0 && revcomp(a:bver, b:"4.7.2")<0) {
  txt += 'Package kdelibs version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"rekonq");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.0")<0) {
  txt += 'Package rekonq version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}