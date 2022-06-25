###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2231_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for znc openSUSE-SU-2018:2231-1 (znc)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851841");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-08-08 05:51:19 +0200 (Wed, 08 Aug 2018)");
  script_cve_id("CVE-2018-14055", "CVE-2018-14056");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for znc openSUSE-SU-2018:2231-1 (znc)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'znc'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for znc fixes the following issues:

  - Update to version 1.7.1

  * CVE-2018-14055: non-admin user could gain admin privileges and shell
  access by injecting values into znc.conf (bnc#1101281)

  * CVE-2018-14056: path traversal in HTTP handler via ../ in a web skin
  name. (bnc#1101280)

  - Update to version 1.7.0

  * Make ZNC UI translateable to different languages

  * Configs written before ZNC 0.206 can't be read anymore

  * Implement IRCv3.2 capabilities away-notify, account-notify,
  extended-join

  * Implement IRCv3.2 capabilities echo-message, cap-notify on the 'client
  side'

  * Update capability names as they are named in IRCv3.2:
  znc.in/server-time-iso-server-time, znc.in/batch batch. Old names
  will continue working for a while, then will be removed in some future
  version.

  * Make ZNC request server-time from server when available

  * Add 'AuthOnlyViaModule' global/user setting

  * Stop defaulting real name to 'Got ZNC?'

  * Add SNI SSL client support

  * Add support for CIDR notation in allowed hosts list and in trusted
  proxy list

  * Add network-specific config for cert validation in addition to
  user-supplied fingerprints: TrustAllCerts, defaults to false, and
  TrustPKI, defaults to true.

  * Add /attach command for symmetry with /detach. Unlike /join it allows
  wildcards.

  - Update to version 1.6.6:

  * Fix use-after-free in znc --makepem. It was broken for a long time,
  but started segfaulting only now. This is a useability fix, not a
  security fix, because self-signed (or signed by a CA) certificates can
  be created without using --makepem, and then combined into znc.pem.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-819=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-819=1");
  script_tag(name:"affected", value:"znc on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-08/msg00019.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"znc", rpm:"znc~1.7.1~20.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"znc-debuginfo", rpm:"znc-debuginfo~1.7.1~20.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"znc-debugsource", rpm:"znc-debugsource~1.7.1~20.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"znc-devel", rpm:"znc-devel~1.7.1~20.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"znc-perl", rpm:"znc-perl~1.7.1~20.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"znc-perl-debuginfo", rpm:"znc-perl-debuginfo~1.7.1~20.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"znc-python3", rpm:"znc-python3~1.7.1~20.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"znc-python3-debuginfo", rpm:"znc-python3-debuginfo~1.7.1~20.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"znc-tcl", rpm:"znc-tcl~1.7.1~20.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"znc-tcl-debuginfo", rpm:"znc-tcl-debuginfo~1.7.1~20.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"znc-lang", rpm:"znc-lang~1.7.1~20.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
