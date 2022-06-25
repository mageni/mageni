###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for thunderbird RHSA-2013:0145-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-January/msg00020.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870885");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-01-11 16:42:31 +0530 (Fri, 11 Jan 2013)");
  script_cve_id("CVE-2013-0744", "CVE-2013-0746", "CVE-2013-0748", "CVE-2013-0750",
                "CVE-2013-0753", "CVE-2013-0754", "CVE-2013-0758", "CVE-2013-0759",
                "CVE-2013-0762", "CVE-2013-0766", "CVE-2013-0767", "CVE-2013-0769");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for thunderbird RHSA-2013:0145-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"thunderbird on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the processing of malformed content. Malicious
  content could cause Thunderbird to crash or, potentially, execute arbitrary
  code with the privileges of the user running Thunderbird. (CVE-2013-0744,
  CVE-2013-0746, CVE-2013-0750, CVE-2013-0753, CVE-2013-0754, CVE-2013-0762,
  CVE-2013-0766, CVE-2013-0767, CVE-2013-0769)

  A flaw was found in the way Chrome Object Wrappers were implemented.
  Malicious content could be used to cause Thunderbird to execute arbitrary
  code via plug-ins installed in Thunderbird. (CVE-2013-0758)

  A flaw in the way Thunderbird displayed URL values could allow malicious
  content or a user to perform a phishing attack. (CVE-2013-0759)

  An information disclosure flaw was found in the way certain JavaScript
  functions were implemented in Thunderbird. An attacker could use this flaw
  to bypass Address Space Layout Randomization (ASLR) and other security
  restrictions. (CVE-2013-0748)

  Red Hat would like to thank the Mozilla project for reporting these issues.
  Upstream acknowledges Atte Kettunen, Boris Zbarsky, pa_kt, regenrecht,
  Abhishek Arya, Christoph Diehl, Christian Holler, Mats Palmgren, Chiaki
  Ishikawa, Mariusz Mlynski, Masato Kinugawa, and Jesse Ruderman as the
  original reporters of these issues.

  Note: All issues except CVE-2013-0744, CVE-2013-0753, and CVE-2013-0754
  cannot be exploited by a specially-crafted HTML mail message as JavaScript
  is disabled by default for mail messages. They could be exploited another
  way in Thunderbird, for example, when viewing the full remote content of an
  RSS feed.

  All Thunderbird users should upgrade to this updated package, which
  contains Thunderbird version 10.0.12 ESR, which corrects these issues.
  After installing the update, Thunderbird must be restarted for the changes
  to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~10.0.12~3.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"thunderbird-debuginfo", rpm:"thunderbird-debuginfo~10.0.12~3.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
