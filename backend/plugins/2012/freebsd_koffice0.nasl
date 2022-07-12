###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_koffice0.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID aa4d3d73-ef17-11e1-b593-00269ef07d24
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
  script_oid("1.3.6.1.4.1.25623.1.0.71834");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2012-3455", "CVE-2012-3456");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-08-30 11:34:17 -0400 (Thu, 30 Aug 2012)");
  script_name("FreeBSD Ports: koffice");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  koffice
   koffice-kde4
   calligra

CVE-2012-3455
Heap-based buffer overflow in the read function in
filters/words/msword-odf/wv2/src/styles.cpp in the Microsoft import
filter in KOffice 2.3.3 and earlier allows remote attackers to cause a
denial of service (application crash) and possibly execute arbitrary
code via a crafted ODF style in an ODF document.  NOTE: this is the
same vulnerability as CVE-2012-3456, but it was SPLIT by the CNA even
though Calligra and KOffice share the same codebase.
CVE-2012-3456
Heap-based buffer overflow in the read function in
filters/words/msword-odf/wv2/src/styles.cpp in the Microsoft import
filter in Calligra 2.4.3 and earlier allows remote attackers to cause
a denial of service (application crash) and possibly execute arbitrary
code via a crafted ODF style in an ODF document.  NOTE: this is the
same vulnerability as CVE-2012-3455, but it was SPLIT by the CNA even
though Calligra and KOffice share the same codebase.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20120810-1.txt");
  script_xref(name:"URL", value:"http://media.blackhat.com/bh-us-12/Briefings/C_Miller/BH_US_12_Miller_NFC_attack_surface_WP.pdf");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/aa4d3d73-ef17-11e1-b593-00269ef07d24.html");

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

bver = portver(pkg:"koffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.3_18,2")<=0) {
  txt += "Package koffice version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"koffice-kde4");
if(!isnull(bver) && revcomp(a:bver, b:"2.3.3_7")<=0) {
  txt += "Package koffice-kde4 version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"calligra");
if(!isnull(bver) && revcomp(a:bver, b:"2.5.0")<0) {
  txt += "Package calligra version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}