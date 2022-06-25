###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for spamassassin FEDORA-2007-241
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
tag_insight = "SpamAssassin provides you with a way to reduce if not completely eliminate
  Unsolicited Commercial Email (SPAM) from your incoming email.  It can
  be invoked by a MDA such as sendmail or postfix, or can be called from
  a procmail script, .forward file, etc.  It uses a genetic-algorithm
  evolved scoring system to identify messages which look spammy, then
  adds headers to the message so they can be filtered by the user's mail
  reading software.  This distribution includes the spamd/spamc components
  which create a server that considerably speeds processing of mail.

  To enable spamassassin, if you are receiving mail locally, simply add
  this line to your ~/.procmailrc:
  INCLUDERC=/etc/mail/spamassassin/spamassassin-default.rc
  
  To filter spam for all users, add that line to /etc/procmailrc
  (creating if necessary).";

tag_affected = "spamassassin on Fedora Core 6";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-February/msg00102.html");
  script_oid("1.3.6.1.4.1.25623.1.0.308702");
  script_version("$Revision: 6622 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 07:52:50 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:01:32 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_xref(name: "FEDORA", value: "2007-241");
  script_cve_id("CVE-2007-0451");
  script_name( "Fedora Update for spamassassin FEDORA-2007-241");

  script_tag(name:"summary", value:"Check for the Version of spamassassin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora_core", "ssh/login/rpms");
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

if(release == "FC6")
{

  if ((res = isrpmvuln(pkg:"spamassassin", rpm:"spamassassin~3.1.8~1.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/spamassassin", rpm:"x86_64/spamassassin~3.1.8~1.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/spamassassin-debuginfo", rpm:"x86_64/debug/spamassassin-debuginfo~3.1.8~1.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/spamassassin-debuginfo", rpm:"i386/debug/spamassassin-debuginfo~3.1.8~1.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/spamassassin", rpm:"i386/spamassassin~3.1.8~1.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
