###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for thunderbird RHSA-2011:1342-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-September/msg00046.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870657");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:44:09 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-2372", "CVE-2011-2995", "CVE-2011-2998",
                "CVE-2011-2999", "CVE-2011-3000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for thunderbird RHSA-2011:1342-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"thunderbird on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the processing of malformed HTML content. An
  HTML mail message containing malicious content could cause Thunderbird to
  crash or, potentially, execute arbitrary code with the privileges of the
  user running Thunderbird. (CVE-2011-2995)

  A flaw was found in the way Thunderbird processed the 'Enter' keypress
  event. A malicious HTML mail message could present a download dialog while
  the key is pressed, activating the default 'Open' action. A remote attacker
  could exploit this vulnerability by causing the mail client to open
  malicious web content. (CVE-2011-2372)

  A flaw was found in the way Thunderbird handled Location headers in
  redirect responses. Two copies of this header with different values could
  be a symptom of a CRLF injection attack against a vulnerable server.
  Thunderbird now treats two copies of the Location, Content-Length, or
  Content-Disposition header as an error condition. (CVE-2011-3000)

  A flaw was found in the way Thunderbird handled frame objects with certain
  names. An attacker could use this flaw to cause a plug-in to grant its
  content access to another site or the local file system, violating the
  same-origin policy. (CVE-2011-2999)

  An integer underflow flaw was found in the way Thunderbird handled large
  JavaScript regular expressions. An HTML mail message containing malicious
  JavaScript could cause Thunderbird to access already freed memory, causing
  Thunderbird to crash or, potentially, execute arbitrary code with the
  privileges of the user running Thunderbird. (CVE-2011-2998)

  All Thunderbird users should upgrade to this updated package, which
  resolves these issues. All running instances of Thunderbird must be
  restarted for the update to take effect.");
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

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~3.1.15~1.el6_1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"thunderbird-debuginfo", rpm:"thunderbird-debuginfo~3.1.15~1.el6_1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
