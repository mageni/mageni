###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_linux-flashplugin19.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 53e531a7-e559-11e0-b481-001b2134ef46
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
  script_oid("1.3.6.1.4.1.25623.1.0.70414");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-10-16 23:01:53 +0200 (Sun, 16 Oct 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-2426", "CVE-2011-2427", "CVE-2011-2428", "CVE-2011-2429", "CVE-2011-2430", "CVE-2011-2444");
  script_name("FreeBSD Ports: linux-flashplugin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  linux-flashplugin
   linux-f10-flashplugin

CVE-2011-2426
Stack-based buffer overflow in the ActionScript Virtual Machine (AVM)
component in Adobe Flash Player before 10.3.183.10 on Windows, Mac OS
X, Linux, and Solaris, and before 10.3.186.7 on Android, allows remote
attackers to execute arbitrary code via unspecified vectors.
CVE-2011-2427
Stack-based buffer overflow in the ActionScript Virtual Machine (AVM)
component in Adobe Flash Player before 10.3.183.10 on Windows, Mac OS
X, Linux, and Solaris, and before 10.3.186.7 on Android, allows
attackers to execute arbitrary code or cause a denial of service via
unspecified vectors.
CVE-2011-2428
Adobe Flash Player before 10.3.183.10 on Windows, Mac OS X, Linux, and
Solaris, and before 10.3.186.7 on Android, allows attackers to execute
arbitrary code or cause a denial of service (browser crash) via
unspecified vectors, related to a 'logic error issue.'
CVE-2011-2429
Adobe Flash Player before 10.3.183.10 on Windows, Mac OS X, Linux, and
Solaris, and before 10.3.186.7 on Android, allows attackers to bypass
intended access restrictions and obtain sensitive information via
unspecified vectors, related to a 'security control bypass.'
CVE-2011-2430
Adobe Flash Player before 10.3.183.10 on Windows, Mac OS X, Linux, and
Solaris, and before 10.3.186.7 on Android, allows remote attackers to
execute arbitrary code via crafted streaming media, related to a
'logic error vulnerability.'
CVE-2011-2444
Cross-site scripting (XSS) vulnerability in Adobe Flash Player before
10.3.183.10 on Windows, Mac OS X, Linux, and Solaris, and before
10.3.186.7 on Android, allows remote attackers to inject arbitrary web
script or HTML via a crafted URL, related to a 'universal cross-site
scripting issue, ' as exploited in the wild in September 2011.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://www.adobe.com/support/security/bulletins/apsb11-26.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/53e531a7-e559-11e0-b481-001b2134ef46.html");

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

bver = portver(pkg:"linux-flashplugin");
if(!isnull(bver) && revcomp(a:bver, b:"9.0r289")<=0) {
  txt += 'Package linux-flashplugin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-f10-flashplugin");
if(!isnull(bver) && revcomp(a:bver, b:"10.3r183.10")<0) {
  txt += 'Package linux-f10-flashplugin version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}