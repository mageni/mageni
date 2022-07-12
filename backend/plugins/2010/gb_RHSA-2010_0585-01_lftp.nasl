###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for lftp RHSA-2010:0585-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "LFTP is a sophisticated file transfer program for the FTP and HTTP
  protocols. Like Bash, it has job control and uses the Readline library for
  input. It has bookmarks, built-in mirroring, and can transfer several files
  in parallel. It is designed with reliability in mind.

  It was discovered that lftp trusted the file name provided in the
  Content-Disposition HTTP header. A malicious HTTP server could use this
  flaw to write or overwrite files in the current working directory of a
  victim running lftp, by sending a different file from what the victim
  requested. (CVE-2010-2251)
  
  To correct this flaw, the following changes were made to lftp: the
  &quot;xfer:clobber&quot; option now defaults to &quot;no&quot;, causing lftp to not overwrite
  existing files, and a new option, &quot;xfer:auto-rename&quot;, which defaults to
  &quot;no&quot;, has been introduced to control whether lftp should use
  server-suggested file names. Refer to the &quot;Settings&quot; section of the lftp(1)
  manual page for additional details on changing lftp settings.
  
  All lftp users should upgrade to this updated package, which contains a
  backported patch to correct this issue.";

tag_affected = "lftp on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-August/msg00005.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314512");
  script_version("$Revision: 8495 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-06 10:34:50 +0200 (Fri, 06 Aug 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2010:0585-01");
  script_cve_id("CVE-2010-2251");
  script_name("RedHat Update for lftp RHSA-2010:0585-01");

  script_tag(name: "summary" , value: "Check for the Version of lftp");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"lftp", rpm:"lftp~3.7.11~4.el5_5.3", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lftp-debuginfo", rpm:"lftp-debuginfo~3.7.11~4.el5_5.3", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
