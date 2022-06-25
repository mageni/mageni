###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_linux-f10-flashplugin0.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 9da3834b-6a50-11e1-91af-003067b2972c
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
  script_oid("1.3.6.1.4.1.25623.1.0.71158");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2012-0768", "CVE-2012-0769");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-03-12 11:35:07 -0400 (Mon, 12 Mar 2012)");
  script_name("FreeBSD Ports: linux-f10-flashplugin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: linux-f10-flashplugin

CVE-2012-0768
The Matrix3D component in Adobe Flash Player before 10.3.183.16 and
11.x before 11.1.102.63 on Windows, Mac OS X, Linux, and Solaris,
before 11.1.111.7 on Android 2.x and 3.x, and before 11.1.115.7 on
Android 4.x allows attackers to execute arbitrary code or cause a
denial of service (memory corruption) via unspecified vectors.

CVE-2012-0769
Adobe Flash Player before 10.3.183.16 and 11.x before 11.1.102.63 on
Windows, Mac OS X, Linux, and Solaris, before 11.1.111.7 on Android
2.x and 3.x, and before 11.1.115.7 on Android 4.x does not properly
handle integers, which allows attackers to obtain sensitive
information via unspecified vectors.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://www.adobe.com/support/security/bulletins/apsb12-05.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/9da3834b-6a50-11e1-91af-003067b2972c.html");

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

bver = portver(pkg:"linux-f10-flashplugin");
if(!isnull(bver) && revcomp(a:bver, b:"11.1r102.63")<0) {
  txt += "Package linux-f10-flashplugin version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}