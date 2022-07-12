###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2019_0052_1.nasl 13489 2019-02-06 09:12:08Z cfischer $
#
# SuSE Update for mutt openSUSE-SU-2019:0052-1 (mutt)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852239");
  script_version("$Revision: 13489 $");
  script_cve_id("CVE-2014-9116", "CVE-2018-14349", "CVE-2018-14350", "CVE-2018-14351",
                "CVE-2018-14352", "CVE-2018-14353", "CVE-2018-14354", "CVE-2018-14355",
                "CVE-2018-14356", "CVE-2018-14357", "CVE-2018-14358", "CVE-2018-14359",
                "CVE-2018-14360", "CVE-2018-14361", "CVE-2018-14362", "CVE-2018-14363");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 10:12:08 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-18 04:01:24 +0100 (Fri, 18 Jan 2019)");
  script_name("SuSE Update for mutt openSUSE-SU-2019:0052-1 (mutt)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-01/msg00018.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mutt'
  package(s) announced via the openSUSE-SU-2019:0052_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mutt fixes the following issues:

  Security issues fixed:

  - bsc#1101428: Mutt 1.10.1 security release update.

  - CVE-2018-14351: Fix imap/command.c that mishandles long IMAP status
  mailbox literal count size (bsc#1101583).

  - CVE-2018-14353: Fix imap_quote_string in imap/util.c that has an integer
  underflow (bsc#1101581).

  - CVE-2018-14362: Fix pop.c that does not forbid characters that may have
  unsafe interaction with message-cache pathnames (bsc#1101567).

  - CVE-2018-14354: Fix arbitrary command execution from remote IMAP servers
  via backquote characters (bsc#1101578).

  - CVE-2018-14352: Fix imap_quote_string in imap/util.c that does not leave
  room for quote characters (bsc#1101582).

  - CVE-2018-14356: Fix pop.c that mishandles a zero-length UID
  (bsc#1101576).

  - CVE-2018-14355: Fix imap/util.c that mishandles '..' directory traversal
  in a mailbox name (bsc#1101577).

  - CVE-2018-14349: Fix imap/command.c that mishandles a NO response without
  a message (bsc#1101589).

  - CVE-2018-14350: Fix imap/message.c that has a stack-based buffer
  overflow for a FETCH response with along INTERNALDATE field
  (bsc#1101588).

  - CVE-2018-14363: Fix newsrc.c that does not properlyrestrict '/'
  characters that may have unsafe interaction with cache pathnames
  (bsc#1101566).

  - CVE-2018-14359: Fix buffer overflow via base64 data (bsc#1101570).

  - CVE-2018-14358: Fix imap/message.c that has a stack-based buffer
  overflow for a FETCH response with along RFC822.SIZE field (bsc#1101571).

  - CVE-2018-14360: Fix nntp_add_group in newsrc.c that has a stack-based
  buffer overflow because of incorrect sscanf usage (bsc#1101569).

  - CVE-2018-14357: Fix that remote IMAP servers are allowed to execute
  arbitrary commands via backquote characters (bsc#1101573).

  - CVE-2018-14361: Fix that nntp.c proceeds even if memory allocation fails
  for messages data (bsc#1101568).

  Bug fixes:

  - mutt reports as neomutt and incorrect version (bsc#1094717)

  - No sidebar available in mutt 1.6.1 from Tumbleweed snapshot 20160517
  (bsc#980830)

  - mutt-1.6.1 unusable when built with --enable-sidebar (bsc#982129)

  - (neo)mutt displaying times in Zulu time (bsc#1061343)

  - mutt unconditionally segfaults when displaying a message (bsc#986534)

  - For openSUSE Leap 42.3, retain split of -lang and -doc (boo#1120935)

  This update was imported from the SUSE:SLE-12:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-52=1");

  script_tag(name:"affected", value:"mutt on openSUSE Leap 42.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"mutt-doc", rpm:"mutt-doc~1.10.1~2.5.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mutt-lang", rpm:"mutt-lang~1.10.1~2.5.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mutt", rpm:"mutt~1.10.1~2.5.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mutt-debuginfo", rpm:"mutt-debuginfo~1.10.1~2.5.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mutt-debugsource", rpm:"mutt-debugsource~1.10.1~2.5.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
