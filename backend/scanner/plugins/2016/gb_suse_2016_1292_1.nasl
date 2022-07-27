###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_1292_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for ntp openSUSE-SU-2016:1292-1 (ntp)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851310");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-17 13:40:09 +0200 (Tue, 17 May 2016)");
  script_cve_id("CVE-2015-5300", "CVE-2015-7973", "CVE-2015-7974", "CVE-2015-7975",
                "CVE-2015-7976", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979",
                "CVE-2015-8138", "CVE-2015-8139", "CVE-2015-8140", "CVE-2015-8158");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for ntp openSUSE-SU-2016:1292-1 (ntp)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"ntp was updated to version 4.2.8p6 to fix 12 security issues.

  Also yast2-ntp-client was updated to match some sntp syntax changes.
  (bsc#937837)

  These security issues were fixed:

  - CVE-2015-8158: Fixed potential infinite loop in ntpq (bsc#962966).

  - CVE-2015-8138: Zero Origin Timestamp Bypass (bsc#963002).

  - CVE-2015-7979: Off-path Denial of Service (DoS) attack on authenticated
  broadcast mode (bsc#962784).

  - CVE-2015-7978: Stack exhaustion in recursive traversal of restriction
  list (bsc#963000).

  - CVE-2015-7977: reslist NULL pointer dereference (bsc#962970).

  - CVE-2015-7976: ntpq saveconfig command allows dangerous characters in
  filenames (bsc#962802).

  - CVE-2015-7975: nextvar() missing length check (bsc#962988).

  - CVE-2015-7974: Skeleton Key: Missing key check allows impersonation
  between authenticated peers (bsc#962960).

  - CVE-2015-7973: Replay attack on authenticated broadcast mode
  (bsc#962995).

  - CVE-2015-8140: ntpq vulnerable to replay attacks (bsc#962994).

  - CVE-2015-8139: Origin Leak: ntpq and ntpdc, disclose origin (bsc#962997).

  - CVE-2015-5300: MITM attacker could have forced ntpd to make a step
  larger than the panic threshold (bsc#951629).

  These non-security issues were fixed:

  - fate#320758 bsc#975981: Enable compile-time support for MS-SNTP
  (--enable-ntp-signd).  This replaces the w32 patches in 4.2.4 that added
  the authreg directive.

  - bsc#962318: Call /usr/sbin/sntp with full path to synchronize in
  start-ntpd. When run as cron job, /usr/sbin/ is not in the path, which
  caused the synchronization to fail.

  - bsc#782060: Speedup ntpq.

  - bsc#916617: Add /var/db/ntp-kod.

  - bsc#956773: Add ntp-ENOBUFS.patch to limit a warning that might happen
  quite a lot on loaded systems.

  - bsc#951559, bsc#975496: Fix the TZ offset output of sntp during DST.

  - Add ntp-fork.patch and build with threads disabled to allow name
  resolution even when running chrooted.

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

  if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p6~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.8p6~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-debugsource", rpm:"ntp-debugsource~4.2.8p6~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.8p6~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yast2-ntp-client", rpm:"yast2-ntp-client~3.1.22~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yast2-ntp-client-devel-doc", rpm:"yast2-ntp-client-devel-doc~3.1.22~6.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
