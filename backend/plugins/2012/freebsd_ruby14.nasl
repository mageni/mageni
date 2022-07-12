###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_ruby14.nasl 12634 2018-12-04 07:26:26Z cfischer $
#
# Auto generated from VID 3decc87d-2498-11e2-b0c7-000d601460a4
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
  script_oid("1.3.6.1.4.1.25623.1.0.72614");
  script_cve_id("CVE-2012-4522");
  script_version("$Revision: 12634 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 08:26:26 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2012-11-26 12:47:33 -0500 (Mon, 26 Nov 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("FreeBSD Ports: ruby");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: ruby

CVE-2012-4522
The rb_get_path_check function in file.c in Ruby 1.9.3 before
patchlevel 286 and Ruby 2.0.0 before r37163 allows context-dependent
attackers to create files in unexpected locations or with unexpected
names via a NUL byte in a file path.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.ruby-lang.org/en/news/2012/10/12/poisoned-NUL-byte-vulnerability/");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/CVE-2012-4522/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/3decc87d-2498-11e2-b0c7-000d601460a4.html");

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

bver = portver(pkg:"ruby");
if(!isnull(bver) && revcomp(a:bver, b:"1.9.3,1")>0 && revcomp(a:bver, b:"1.9.3.286,1")<0) {
  txt += "Package ruby version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}