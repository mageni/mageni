###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for setroubleshoot RHSA-2008:0061-02
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
tag_insight = "The setroubleshoot packages provide tools to help diagnose SELinux
  problems. When AVC messages occur, an alert is generated that gives
  information about the problem, and how to create a resolution.

  A flaw was found in the way sealert wrote diagnostic messages to a
  temporary file. A local unprivileged user could perform a symbolic link
  attack, and cause arbitrary files, writable by other users, to be
  overwritten when a victim runs sealert. (CVE-2007-5495)
  
  A flaw was found in the way sealert displayed records from the
  setroubleshoot database as unescaped HTML. An local unprivileged attacker
  could cause AVC denial events with carefully crafted process or file names,
  injecting arbitrary HTML tags into the logs, which could be used as a
  scripting attack, or to confuse the user running sealert. (CVE-2007-5496)
  
  Additionally, the following bugs have been fixed in these update packages:
  
  * in certain situations, the sealert process used excessive CPU. These
  alerts are now capped at a maximum of 30, D-Bus is used instead of polling,
  threads causing excessive wake-up have been removed, and more robust
  exception-handling has been added.
  
  * different combinations of the sealert '-a', '-l', '-H', and '-v' options
  did not work as documented.
  
  * the SETroubleShoot browser did not allow multiple entries to be deleted. 
  
  * the SETroubleShoot browser did not display statements that displayed
  whether SELinux was using Enforcing or Permissive mode, particularly when
  warning about SELinux preventions.
  
  * in certain cases, the SETroubleShoot browser gave incorrect instructions
  regarding paths, and would not display the full paths to files.
  
  * adding an email recipient to the recipients option from the
  /etc/setroubleshoot/setroubleshoot.cfg file and then generating an SELinux
  denial caused a traceback error. The recipients option has been removed;
  email addresses are now managed through the SETroubleShoot browser by
  navigating to File -&gt; Edit Email Alert List, or by editing the
  /var/lib/setroubleshoot/email_alert_recipients file.
  
  * the setroubleshoot browser incorrectly displayed a period between the
  httpd_sys_content_t context and the directory path.
  
  * on the PowerPC architecture, The get_credentials() function in
  access_control.py would generate an exception when it called the
  socket.getsockopt() function.
  
  * The code which handles path information has been completely rewritten so
  that assumptions on path information which were misleading are no longer
  made. If the path inf ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "setroubleshoot on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-May/msg00017.html");
  script_oid("1.3.6.1.4.1.25623.1.0.306123");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2008:0061-02");
  script_cve_id("CVE-2007-5495", "CVE-2007-5496");
  script_name( "RedHat Update for setroubleshoot RHSA-2008:0061-02");

  script_tag(name:"summary", value:"Check for the Version of setroubleshoot");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"setroubleshoot", rpm:"setroubleshoot~2.0.5~3.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"setroubleshoot-plugins", rpm:"setroubleshoot-plugins~2.0.4~2.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"setroubleshoot-server", rpm:"setroubleshoot-server~2.0.5~3.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
