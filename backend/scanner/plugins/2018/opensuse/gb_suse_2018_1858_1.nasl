###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1858_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for mailman openSUSE-SU-2018:1858-1 (mailman)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851805");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-07-01 05:47:18 +0200 (Sun, 01 Jul 2018)");
  script_cve_id("CVE-2018-0618");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for mailman openSUSE-SU-2018:1858-1 (mailman)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mailman'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"This update for mailman to version 2.1.27 fixes the following issues:

  This security issue was fixed:

  - CVE-2018-0618: Additional protections against injecting scripts into
  listinfo and error messages pages (bsc#1099510).

  These non-security issues were fixed:

  - The hash generated when SUBSCRIBE_FORM_SECRET is set could have been the
  same as one generated at the same time for a different list and IP
  address.

  - An option has been added to bin/add_members to issue invitations instead
  of immediately adding members.

  - A new BLOCK_SPAMHAUS_LISTED_IP_SUBSCRIBE setting has been added to
  enable blocking web subscribes from IPv4 addresses listed in Spamhaus
  SBL, CSS or XBL.  It will work with IPv6 addresses if Python's
  py2-ipaddress module is installed.  The module can be installed via pip
  if not included in your Python.

  - Mailman has a new 'security' log and logs authentication failures to the
  various web CGI functions.  The logged data include the remote IP and
  can be used to automate blocking of IPs with something like fail2ban.
  Since Mailman 2.1.14, these have returned an http 401 status and the
  information should be logged by the web server, but this new log makes
  that more convenient.  Also, the 'mischief' log entries for 'hostile
  listname' not include the remote IP if available.

  - admin notices of (un)subscribes now may give the source of the action.
  This consists of a %(whence)s replacement that has been added to the
  admin(un)subscribeack.txt templates.  Thanks to Yasuhito FUTATSUKI for
  updating the non-English templates and help with internationalizing the
  reasons.

  - there is a new BLOCK_SPAMHAUS_LISTED_DBL_SUBSCRIBE setting to enable
  blocking web subscribes for addresses in domains listed in the Spamhaus
  DBL.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-691=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-691=1");
  script_tag(name:"affected", value:"mailman on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-06/msg00053.html");
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

  if ((res = isrpmvuln(pkg:"mailman", rpm:"mailman~2.1.27~2.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mailman-debuginfo", rpm:"mailman-debuginfo~2.1.27~2.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mailman-debugsource", rpm:"mailman-debugsource~2.1.27~2.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
