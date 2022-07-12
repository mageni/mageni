###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_pure-ftpd.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 1495f931-8522-11e0-a1c1-00215c6a37bb
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
  script_oid("1.3.6.1.4.1.25623.1.0.69765");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
  script_cve_id("CVE-2011-0418", "CVE-2011-1575");
  script_bugtraq_id(46767);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("FreeBSD Ports: pure-ftpd");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: pure-ftpd

CVE-2011-0418
The glob implementation in Pure-FTPd before 1.0.32, and in libc in
NetBSD 5.1, does not properly expand expressions containing curly
brackets, which allows remote authenticated users to cause a denial of
service (memory consumption) via a crafted FTP STAT command.

CVE-2011-1575
The STARTTLS implementation in ftp_parser.c in Pure-FTPd before 1.0.30
does not properly restrict I/O buffering, which allows
man-in-the-middle attackers to insert commands into encrypted FTP
sessions by sending a cleartext command that is processed after TLS is
in place, related to a 'plaintext command injection' attack, a similar
issue to CVE-2011-0411.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

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

bver = portver(pkg:"pure-ftpd");
if(!isnull(bver) && revcomp(a:bver, b:"1.0.32")<0) {
  txt += 'Package pure-ftpd version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}