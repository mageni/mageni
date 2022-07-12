###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_wordpress12.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 8c93e997-30e0-11e0-b300-485d605f4717
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
  script_oid("1.3.6.1.4.1.25623.1.0.68955");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-03-05 22:25:39 +0100 (Sat, 05 Mar 2011)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2010-4257");
  script_name("FreeBSD Ports: wordpress");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  wordpress
   de-wordpress
   zh-wordpress-zh_CN
   zh-wordpress-zh_TW

CVE-2010-4257
SQL injection vulnerability in the do_trackbacks function in
wp-includes/comment.php in WordPress before 3.0.2 allows remote
authenticated users to execute arbitrary SQL commands via the Send
Trackbacks field.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.cvedetails.com/cve/CVE-2010-4257/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/8c93e997-30e0-11e0-b300-485d605f4717.html");

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

bver = portver(pkg:"wordpress");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.2,1")<0) {
  txt += 'Package wordpress version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"de-wordpress");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.2")<0) {
  txt += 'Package de-wordpress version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"zh-wordpress-zh_CN");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.2")<0) {
  txt += 'Package zh-wordpress-zh_CN version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"zh-wordpress-zh_TW");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.2")<0) {
  txt += 'Package zh-wordpress-zh_TW version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}