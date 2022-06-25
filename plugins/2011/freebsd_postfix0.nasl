###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_postfix0.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 3eb2c100-738b-11e0-89f4-001e90d46635
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
  script_oid("1.3.6.1.4.1.25623.1.0.69770");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
  script_cve_id("CVE-2011-1720");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: postfix, postfix-base");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  postfix
   postfix-base
   postfix-current
   postfix-current-base

CVE-2011-1720
The SMTP server in Postfix before 2.5.13, 2.6.x before 2.6.10, 2.7.x
before 2.7.4, and 2.8.x before 2.8.3, when certain Cyrus SASL
authentication methods are enabled, does not create a new server
handle after client authentication fails, which allows remote
attackers to cause a denial of service (heap memory corruption and
daemon crash) or possibly execute arbitrary code via an invalid AUTH
command with one method followed by an AUTH command with a different
method.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.postfix.org/CVE-2011-1720.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/3eb2c100-738b-11e0-89f4-001e90d46635.html");

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

bver = portver(pkg:"postfix");
if(!isnull(bver) && revcomp(a:bver, b:"2.8.*,1")>=0 && revcomp(a:bver, b:"2.8.3,1")<0) {
  txt += 'Package postfix version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.7.*,1")>=0 && revcomp(a:bver, b:"2.7.4,1")<0) {
  txt += 'Package postfix version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.6.*,1")>=0 && revcomp(a:bver, b:"2.6.10,1")<0) {
  txt += 'Package postfix version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.5.*,2")>=0 && revcomp(a:bver, b:"2.5.13,2")<0) {
  txt += 'Package postfix version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.4.16,1")<=0) {
  txt += 'Package postfix version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"postfix-base");
if(!isnull(bver) && revcomp(a:bver, b:"2.8.*,1")>=0 && revcomp(a:bver, b:"2.8.3,1")<0) {
  txt += 'Package postfix-base version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.7.*,1")>=0 && revcomp(a:bver, b:"2.7.4,1")<0) {
  txt += 'Package postfix-base version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.6.*,1")>=0 && revcomp(a:bver, b:"2.6.10,1")<0) {
  txt += 'Package postfix-base version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.5.*,2")>=0 && revcomp(a:bver, b:"2.5.13,2")<0) {
  txt += 'Package postfix-base version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.4.16,1")<=0) {
  txt += 'Package postfix-base version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"postfix-current");
if(!isnull(bver) && revcomp(a:bver, b:"2.9.20110501,4")<0) {
  txt += 'Package postfix-current version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"postfix-current-base");
if(!isnull(bver) && revcomp(a:bver, b:"2.9.20110501,4")<0) {
  txt += 'Package postfix-current-base version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}