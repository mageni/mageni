###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_1329_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for ntp openSUSE-SU-2016:1329-1 (ntp)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.851318");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-19 05:22:13 +0200 (Thu, 19 May 2016)");
  script_cve_id("CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7974", "CVE-2016-1547",
                "CVE-2016-1548", "CVE-2016-1549", "CVE-2016-1550", "CVE-2016-1551",
                "CVE-2016-2516", "CVE-2016-2517", "CVE-2016-2518", "CVE-2016-2519");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for ntp openSUSE-SU-2016:1329-1 (ntp)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for ntp to 4.2.8p7 fixes the following issues:

  * CVE-2016-1547, bsc#977459: Validate crypto-NAKs, AKA: CRYPTO-NAK DoS.

  * CVE-2016-1548, bsc#977461: Interleave-pivot

  * CVE-2016-1549, bsc#977451: Sybil vulnerability: ephemeral association
  attack.

  * CVE-2016-1550, bsc#977464: Improve NTP security against buffer
  comparison timing attacks.

  * CVE-2016-1551, bsc#977450: Refclock impersonation vulnerability

  * CVE-2016-2516, bsc#977452: Duplicate IPs on unconfig directives will
  cause an assertion botch in ntpd.

  * CVE-2016-2517, bsc#977455: remote configuration trustedkey/
  requestkey/controlkey values are not properly validated.

  * CVE-2016-2518, bsc#977457: Crafted addpeer with hmode   7 causes array
  wraparound with MATCH_ASSOC.

  * CVE-2016-2519, bsc#977458: ctl_getitem() return value not always checked.

  * This update also improves the fixes for: CVE-2015-7704, CVE-2015-7705,
  CVE-2015-7974

  Bugs fixed:

  - Restrict the parser in the startup script to the first
  occurrence of 'keys' and 'controlkey' in ntp.conf (bsc#957226).

  This update was imported from the SUSE:SLE-12-SP1:Update update project.");
  script_tag(name:"affected", value:"ntp on openSUSE Leap 42.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p7~21.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.8p7~21.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-debugsource", rpm:"ntp-debugsource~4.2.8p7~21.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.8p7~21.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
