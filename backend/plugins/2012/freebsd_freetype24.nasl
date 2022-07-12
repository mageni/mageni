###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_freetype24.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 54075e39-04ac-11e1-a94e-bcaec565249c
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
  script_oid("1.3.6.1.4.1.25623.1.0.70611");
  script_tag(name:"creation_date", value:"2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2011-3256");
  script_version("$Revision: 11762 $");
  script_name("FreeBSD Ports: freetype2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: freetype2

CVE-2011-3256
FreeType 2 before 2.4.7, as used in CoreGraphics in Apple iOS before
5, Mandriva Enterprise Server 5, and possibly other products, allows
remote attackers to execute arbitrary code or cause a denial of
service (memory corruption) via a crafted font, a different
vulnerability than CVE-2011-0226.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://sourceforge.net/projects/freetype/files/freetype2/2.4.7/README/view");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/attachment.cgi?id=528829&action=diff");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/54075e39-04ac-11e1-a94e-bcaec565249c.html");

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

bver = portver(pkg:"freetype2");
if(!isnull(bver) && revcomp(a:bver, b:"2.4.7")<0) {
  txt += 'Package freetype2 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}