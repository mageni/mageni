###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_samba340.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 56f4b3a6-c82c-11e0-a498-00215c6a37bb
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
  script_oid("1.3.6.1.4.1.25623.1.0.70262");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-2522", "CVE-2011-2694");
  script_bugtraq_id(48901, 48899);
  script_name("FreeBSD Ports: samba34");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  samba34
   samba35

CVE-2011-2522
Multiple cross-site request forgery (CSRF) vulnerabilities in the
Samba Web Administration Tool (SWAT) in Samba 3.x before 3.5.10 allow
remote attackers to hijack the authentication of administrators for
requests that (1) shut down daemons, (2) start daemons, (3) add
shares, (4) remove shares, (5) add printers, (6) remove printers, (7)
add user accounts, or (8) remove user accounts, as demonstrated by
certain start, stop, and restart parameters to the status program.

CVE-2011-2694
Cross-site scripting (XSS) vulnerability in the chg_passwd function in
web/swat.c in the Samba Web Administration Tool (SWAT) in Samba 3.x
before 3.5.10 allows remote authenticated administrators to inject
arbitrary web script or HTML via the username parameter to the passwd
program (aka the user field to the Change Password page).");

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

bver = portver(pkg:"samba34");
if(!isnull(bver) && revcomp(a:bver, b:"3.4")>0 && revcomp(a:bver, b:"3.4.14")<0) {
  txt += 'Package samba34 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"samba35");
if(!isnull(bver) && revcomp(a:bver, b:"3.5")>0 && revcomp(a:bver, b:"3.5.10")<0) {
  txt += 'Package samba35 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}