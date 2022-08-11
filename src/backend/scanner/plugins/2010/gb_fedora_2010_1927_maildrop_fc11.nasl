###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for maildrop FEDORA-2010-1927
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
tag_insight = "maildrop is the mail filter/mail delivery agent that's used by the
  Courier Mail Server. This is a standalone build of the maildrop mail
  filter that can be used with other mail servers.

  maildrop is a replacement for your local mail delivery agent. maildrop
  reads a mail message from standard input, then delivers the message to
  your mailbox. maildrop knows how to deliver mail to mbox-style
  mailboxes, and maildirs.
  
  maildrop optionally reads instructions from a file, which describe how
  to filter incoming mail. These instructions can direct maildrop to
  deliver the message to an alternate mailbox, or forward it somewhere
  else. Unlike procmail, maildrop uses a structured filtering language.
  
  maildrop is written in C++, and is significantly larger than
  procmail. However, it uses resources much more efficiently. Unlike
  procmail, maildrop will not read a 10 megabyte mail message into
  memory. Large messages are saved in a temporary file, and are filtered
  from the temporary file. If the standard input to maildrop is a file,
  and not a pipe, a temporary file will not be necessary.
  
  maildrop checks the mail delivery instruction syntax from the filter
  file, before attempting to deliver a message. Unlike procmail, if the
  filter file contains syntax errors, maildrop terminates without
  delivering the message. The user can fix the typo without causing any
  mail to be lost.";

tag_affected = "maildrop on Fedora 11";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-February/035170.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314810");
  script_version("$Revision: 8469 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 08:58:21 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-02 08:38:02 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2010-1927");
  script_cve_id("CVE-2010-0301");
  script_name("Fedora Update for maildrop FEDORA-2010-1927");

  script_tag(name: "summary" , value: "Check for the Version of maildrop");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

if(release == "FC11")
{

  if ((res = isrpmvuln(pkg:"maildrop", rpm:"maildrop~2.4.0~12.fc11", rls:"FC11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
