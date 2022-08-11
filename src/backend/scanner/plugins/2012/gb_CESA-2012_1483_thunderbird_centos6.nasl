###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for thunderbird CESA-2012:1483 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-November/019009.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881543");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-11-23 11:46:46 +0530 (Fri, 23 Nov 2012)");
  script_cve_id("CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4207", "CVE-2012-4209",
                "CVE-2012-4214", "CVE-2012-4215", "CVE-2012-4216", "CVE-2012-5829",
                "CVE-2012-5830", "CVE-2012-5833", "CVE-2012-5835", "CVE-2012-5839",
                "CVE-2012-5840", "CVE-2012-5841", "CVE-2012-5842");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for thunderbird CESA-2012:1483 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"thunderbird on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the processing of malformed content. Malicious
  content could cause Thunderbird to crash or, potentially, execute arbitrary
  code with the privileges of the user running Thunderbird. (CVE-2012-4214,
  CVE-2012-4215, CVE-2012-4216, CVE-2012-5829, CVE-2012-5830, CVE-2012-5833,
  CVE-2012-5835, CVE-2012-5839, CVE-2012-5840, CVE-2012-5842)

  A buffer overflow flaw was found in the way Thunderbird handled GIF
  (Graphics Interchange Format) images. Content containing a malicious GIF
  image could cause Thunderbird to crash or, possibly, execute arbitrary code
  with the privileges of the user running Thunderbird. (CVE-2012-4202)

  A flaw was found in the way Thunderbird decoded the HZ-GB-2312 character
  encoding. Malicious content could cause Thunderbird to run JavaScript code
  with the permissions of different content. (CVE-2012-4207)

  A flaw was found in the location object implementation in Thunderbird.
  Malicious content could possibly use this flaw to allow restricted content
  to be loaded by plug-ins. (CVE-2012-4209)

  A flaw was found in the way cross-origin wrappers were implemented.
  Malicious content could use this flaw to perform cross-site scripting
  attacks. (CVE-2012-5841)

  A flaw was found in the evalInSandbox implementation in Thunderbird.
  Malicious content could use this flaw to perform cross-site scripting
  attacks. (CVE-2012-4201)

  Red Hat would like to thank the Mozilla project for reporting these issues.
  Upstream acknowledges Abhishek Arya, miaubiz, Jesse Ruderman, Andrew
  McCreight, Bob Clary, Kyle Huey, Atte Kettunen, Masato Kinugawa, Mariusz
  Mlynski, Bobby Holley, and moz_bug_r_a4 as the original reporters of
  these issues.

  Note: All issues except CVE-2012-4202 cannot be exploited by a
  specially-crafted HTML mail message as JavaScript is disabled by default
  for mail messages. They could be exploited another way in Thunderbird, for
  example, when viewing the full remote content of an RSS feed.

  All Thunderbird users should upgrade to this updated package, which
  contains Thunderbird version 10.0.11 ESR, which corrects these issues.
  After installing the update, Thunderbird must be restarted for the changes
  to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~10.0.11~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
