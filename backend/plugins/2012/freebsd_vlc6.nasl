###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_vlc6.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 62f36dfd-ff56-11e1-8821-001b2134ef46
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
  script_oid("1.3.6.1.4.1.25623.1.0.72196");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2012-1775", "CVE-2012-1776");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-09-15 04:25:48 -0400 (Sat, 15 Sep 2012)");
  script_name("FreeBSD Ports: vlc");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: vlc

CVE-2012-1775
Stack-based buffer overflow in VideoLAN VLC media player before 2.0.1
allows remote attackers to execute arbitrary code via a crafted MMS://
stream.
CVE-2012-1776
Multiple heap-based buffer overflows in VideoLAN VLC media player
before 2.0.1 allow remote attackers to cause a denial of service
(application crash) or possibly execute arbitrary code via a crafted
Real RTSP stream.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.videolan.org/security/sa1201.html");
  script_xref(name:"URL", value:"http://www.videolan.org/security/sa1202.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/62f36dfd-ff56-11e1-8821-001b2134ef46.html");

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

bver = portver(pkg:"vlc");
if(!isnull(bver) && revcomp(a:bver, b:"2.0.1,3")<0) {
  txt += "Package vlc version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}