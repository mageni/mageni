###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_apache21.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID de2bc01f-dc44-11e1-9f4d-002354ed89bc
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
  script_oid("1.3.6.1.4.1.25623.1.0.71512");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2012-0883");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
  script_name("FreeBSD Ports: apache");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  apache
   apache-event
   apache-itk
   apache-peruser
   apache-worker

CVE-2012-0883
envvars (aka envvars-std) in the Apache HTTP Server before 2.4.2
places a zero-length directory name in the LD_LIBRARY_PATH, which
allows local users to gain privileges via a Trojan horse DSO in the
current working directory during execution of apachectl.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_24.html");
  script_xref(name:"URL", value:"http://www.apache.org/dist/httpd/CHANGES_2.4.2");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/de2bc01f-dc44-11e1-9f4d-002354ed89bc.html");

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

bver = portver(pkg:"apache");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.22_5")<=0) {
  txt += "Package apache version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"apache-event");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.22_5")<=0) {
  txt += "Package apache-event version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"apache-itk");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.22_5")<=0) {
  txt += "Package apache-itk version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"apache-peruser");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.22_5")<=0) {
  txt += "Package apache-peruser version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"apache-worker");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.22_5")<=0) {
  txt += "Package apache-worker version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}