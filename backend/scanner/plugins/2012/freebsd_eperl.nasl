###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_eperl.nasl 11763 2018-10-05 11:31:35Z cfischer $
#
# Auto generated from VID 73efb1b7-07ec-11e2-a391-000c29033c32
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
  script_oid("1.3.6.1.4.1.25623.1.0.72446");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0733");
  script_bugtraq_id(2912);
  script_version("$Revision: 11763 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 13:31:35 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-10-03 11:11:06 -0400 (Wed, 03 Oct 2012)");
  script_name("FreeBSD Ports: eperl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: eperl

CVE-2001-0733
The #sinclude directive in Embedded Perl (ePerl) 2.2.14 and earlier
allows a remote attacker to execute arbitrary code by modifying the
'sinclude' file to point to another file that contains a #include
directive that references a file that contains the code.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
software upgrades.");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.shmoo.com/mail/bugtraq/jun01/msg00286.shtml");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/6743");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/73efb1b7-07ec-11e2-a391-000c29033c32.html");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"eperl");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.14_4")<=0) {
  txt += "Package eperl version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}