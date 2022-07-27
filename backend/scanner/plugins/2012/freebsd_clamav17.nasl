###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_clamav17.nasl 14170 2019-03-14 09:24:12Z cfischer $
#
# Auto generated from VID eb12ebee-b7af-11e1-b5e0-000c299b62e1
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
  script_oid("1.3.6.1.4.1.25623.1.0.71536");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2012-1419", "CVE-2012-1457", "CVE-2012-1458", "CVE-2012-1459");
  script_version("$Revision: 14170 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 10:24:12 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
  script_name("FreeBSD Ports: clamav");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  clamav
   clamav-devel

CVE-2012-1419
The TAR file parser in ClamAV 0.96.4 and Quick Heal (aka Cat
QuickHeal) 11.00 allows remote attackers to bypass malware detection
via a POSIX TAR file with an initial [aliases] character sequence.
NOTE: this may later be SPLIT into multiple CVEs if additional
information is published showing that the error occurred independently
in different TAR parser implementations.
CVE-2012-1457
The TAR file parser in Avira AntiVir 7.11.1.163, Antiy Labs AVL SDK
2.0.3.7, avast! Antivirus 4.8.1351.0 and 5.0.677.0, AVG Anti-Virus
10.0.0.1190, Bitdefender 7.2, Quick Heal (aka Cat QuickHeal) 11.00,
ClamAV 0.96.4, Command Antivirus 5.2.11.5, Emsisoft Anti-Malware
5.1.0.1, eSafe 7.0.17.0, F-Prot Antivirus 4.6.2.117, G Data AntiVirus
21, Ikarus Virus Utilities T3 Command Line Scanner 1.1.97.0, Jiangmin
Antivirus 13.0.900, K7 AntiVirus 9.77.3565, Kaspersky Anti-Virus
7.0.0.125, McAfee Anti-Virus Scanning Engine 5.400.0.1158, McAfee
Gateway (formerly Webwasher) 2010.1C, Antimalware Engine 1.1.6402.0 in
Microsoft Security Essentials 2.0, NOD32 Antivirus 5795, Norman
Antivirus 6.06.12, PC Tools AntiVirus 7.0.3.5, Rising Antivirus
22.83.00.03, AVEngine 20101.3.0.103 in Symantec Endpoint Protection
11, Trend Micro AntiVirus 9.120.0.1004, Trend Micro HouseCall
9.120.0.1004, VBA32 3.12.14.2, and VirusBuster 13.6.151.0 allows
remote attackers to bypass malware detection via a TAR archive entry
with a length field that exceeds the total TAR file size.  NOTE: this
may later be SPLIT into multiple CVEs if additional information is
published showing that the error occurred independently in different
TAR parser implementations.

Text truncated. Please see the references for more information.");

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

bver = portver(pkg:"clamav");
if(!isnull(bver) && revcomp(a:bver, b:"0.97.5")<0) {
  txt += "Package clamav version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"clamav-devel");
if(!isnull(bver) && revcomp(a:bver, b:"20120612")<0) {
  txt += "Package clamav-devel version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}