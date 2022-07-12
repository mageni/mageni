###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for evolution28 RHSA-2008:0515-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "Evolution is the integrated collection of e-mail, calendaring, contact
  management, communications and personal information management (PIM) tools
  for the GNOME desktop environment.

  A flaw was found in the way Evolution parsed iCalendar timezone attachment
  data. If the Itip Formatter plug-in was disabled and a user opened a mail
  with a carefully crafted iCalendar attachment, arbitrary code could be
  executed as the user running Evolution. (CVE-2008-1108)
  
  Note: the Itip Formatter plug-in, which allows calendar information
  (attachments with a MIME type of &quot;text/calendar&quot;) to be displayed as part
  of the e-mail message, is enabled by default.
  
  A heap-based buffer overflow flaw was found in the way Evolution parsed
  iCalendar attachments with an overly long &quot;DESCRIPTION&quot; property string. If
  a user responded to a carefully crafted iCalendar attachment in a
  particular way, arbitrary code could be executed as the user running
  Evolution. (CVE-2008-1109).
  
  The particular response required to trigger this vulnerability was as
  follows:
  
  1. Receive the carefully crafted iCalendar attachment.
  2. Accept the associated meeting.
  3. Open the calendar the meeting was in.
  4. Reply to the sender.
  
  Red Hat would like to thank Alin Rad Pop of Secunia Research for
  responsibly disclosing these issues.
  
  All Evolution users should upgrade to these updated packages, which contain
  backported patches which resolves these issues.";

tag_affected = "evolution28 on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-June/msg00004.html");
  script_oid("1.3.6.1.4.1.25623.1.0.310798");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2008:0515-01");
  script_cve_id("CVE-2008-1108", "CVE-2008-1109");
  script_name( "RedHat Update for evolution28 RHSA-2008:0515-01");

  script_tag(name:"summary", value:"Check for the Version of evolution28");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"evolution28", rpm:"evolution28~2.8.0~53.el4_6.3", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution28-debuginfo", rpm:"evolution28-debuginfo~2.8.0~53.el4_6.3", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution28-devel", rpm:"evolution28-devel~2.8.0~53.el4_6.3", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
