###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for firefox RHSA-2010:0501-01
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
tag_insight = "Mozilla Firefox is an open source web browser.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2010-1121, CVE-2010-1200, CVE-2010-1202, CVE-2010-1203)
  
  A flaw was found in the way browser plug-ins interact. It was possible for
  a plug-in to reference the freed memory from a different plug-in, resulting
  in the execution of arbitrary code with the privileges of the user running
  Firefox. (CVE-2010-1198)
  
  Several integer overflow flaws were found in the processing of malformed
  web content. A web page containing malicious content could cause Firefox to
  crash or, potentially, execute arbitrary code with the privileges of the
  user running Firefox. (CVE-2010-1196, CVE-2010-1199)
  
  A focus stealing flaw was found in the way Firefox handled focus changes. A
  malicious website could use this flaw to steal sensitive data from a user,
  such as usernames and passwords. (CVE-2010-1125)
  
  A flaw was found in the way Firefox handled the &quot;Content-Disposition:
  attachment&quot; HTTP header when the &quot;Content-Type: multipart&quot; HTTP header was
  also present. A website that allows arbitrary uploads and relies on the
  &quot;Content-Disposition: attachment&quot; HTTP header to prevent content from being
  displayed inline, could be used by an attacker to serve malicious content
  to users. (CVE-2010-1197)
  
  A flaw was found in the Firefox Math.random() function. This function could
  be used to identify a browsing session and track a user across different
  websites. (CVE-2008-5913)
  
  A flaw was found in the Firefox XML document loading security checks.
  Certain security checks were not being called when an XML document was
  loaded. This could possibly be leveraged later by an attacker to load
  certain resources that violate the security policies of the browser or its
  add-ons. Note that this issue cannot be exploited by only loading an XML
  document. (CVE-2010-0182)
  
  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 3.6.4. You can find a link to the Mozilla advisories
  in the References section of this erratum.
  
  This erratum upgrades Firefox from version 3.0.19 to version 3.6.4. Due to
  the requirements of Firefox 3.6.4, this erratum also provides a number of
  other updated packages, including esc, totem, and yelp.
  
  This erratum also contains multiple bug fixes and numerous enhan ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "firefox on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-June/msg00019.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313849");
  script_version("$Revision: 8228 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 08:29:52 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-06-28 09:16:14 +0200 (Mon, 28 Jun 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2010:0501-01");
  script_cve_id("CVE-2008-5913", "CVE-2010-0182", "CVE-2010-1121", "CVE-2010-1125", "CVE-2010-1196", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1202", "CVE-2010-1203");
  script_name("RedHat Update for firefox RHSA-2010:0501-01");

  script_tag(name: "summary" , value: "Check for the Version of firefox");
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

  if ((res = isrpmvuln(pkg:"devhelp", rpm:"devhelp~0.12~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"devhelp-debuginfo", rpm:"devhelp-debuginfo~0.12~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"devhelp-devel", rpm:"devhelp-devel~0.12~21.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"esc", rpm:"esc~1.1.0~12.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"esc-debuginfo", rpm:"esc-debuginfo~1.1.0~12.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.6.4~8.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~3.6.4~8.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-python2-extras", rpm:"gnome-python2-extras~2.14.2~7.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-python2-extras-debuginfo", rpm:"gnome-python2-extras-debuginfo~2.14.2~7.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-python2-gtkhtml2", rpm:"gnome-python2-gtkhtml2~2.14.2~7.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-python2-gtkmozembed", rpm:"gnome-python2-gtkmozembed~2.14.2~7.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-python2-gtkspell", rpm:"gnome-python2-gtkspell~2.14.2~7.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-python2-libegg", rpm:"gnome-python2-libegg~2.14.2~7.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"totem", rpm:"totem~2.16.7~7.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"totem-debuginfo", rpm:"totem-debuginfo~2.16.7~7.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"totem-devel", rpm:"totem-devel~2.16.7~7.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"totem-mozplugin", rpm:"totem-mozplugin~2.16.7~7.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~1.9.2.4~9.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-debuginfo", rpm:"xulrunner-debuginfo~1.9.2.4~9.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~1.9.2.4~9.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yelp", rpm:"yelp~2.16.0~26.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yelp-debuginfo", rpm:"yelp-debuginfo~2.16.0~26.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
