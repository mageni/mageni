###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_yahoo-ui0.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID aa4f86af-3172-11e2-ad21-20cf30e32f6d
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
  script_oid("1.3.6.1.4.1.25623.1.0.72631");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2012-5881", "CVE-2012-5882");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-12-04 11:43:52 -0500 (Tue, 04 Dec 2012)");
  script_name("FreeBSD Ports: yahoo-ui");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: yahoo-ui

CVE-2012-5881
Cross-site scripting (XSS) vulnerability in the Flash component
infrastructure in YUI 2.4.0 through 2.9.0 allows remote attackers to
inject arbitrary web script or HTML via vectors related to charts.swf,
a similar issue to CVE-2010-4207.
CVE-2012-5882
Cross-site scripting (XSS) vulnerability in the Flash component
infrastructure in YUI 2.5.0 through 2.9.0 allows remote attackers to
inject arbitrary web script or HTML via vectors related to
uploader.swf, a similar issue to CVE-2010-4208.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://yuilibrary.com/support/20121030-vulnerability/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/aa4f86af-3172-11e2-ad21-20cf30e32f6d.html");

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

bver = portver(pkg:"yahoo-ui");
if(!isnull(bver) && revcomp(a:bver, b:"2.8.2")<=0) {
  txt += "Package yahoo-ui version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}