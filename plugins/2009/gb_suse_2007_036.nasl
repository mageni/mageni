###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_036.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for mozilla,MozillaFirefox,MozillaThunderbird SUSE-SA:2007:036
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
tag_insight = "Various Mozilla family browsers have been updated to their current
  security release versions.

  The Mozilla Seamonkey suite was brought to security update version
  1.0.9.

  The Mozilla Firefox browser was brought to security update version
  1.5.0.12 on Novell Linux Desktop 9 and 2.0.0.4 on SUSE Linux Enterprise
  10, SUSE Linux 10.0, 10.1 and openSUSE 10.2.

  The Mozilla Thunderbird mailreader was brought to security update
  version 1.5.0.12 on SUSE Linux 10.0, 10.1 and openSUSE 10.2.

  Note that most of the packages were released some weeks ago already,
  only MozillaFirefox for SLE10 Service Pack 1 was missing and released
  today.

  The following security issues have been fixed:
  - CVE-2007-2871:

  Chris Thomas demonstrated that XUL popups opened by web content
  could be placed outside the boundaries of the content area. This
  could be used to spoof or hide parts of the browser chrome such as
  the location bar.

  - CVE-2007-2870:

  Mozilla contributor moz_bug_r_a4 demonstrated that the
  addEventListener method could be used to inject script into another
  site in violation of the browser's same-origin policy. This could
  be used to access or modify private or valuable information from
  that other site.

  - CVE-2007-1558:

  Gaëtan Leurent informed us of a weakness in APOP authentication
  that could allow an attacker to recover the first part of your mail
  password if the attacker could interpose a malicious mail server on
  your network masquerading as your legitimate mail server. With normal
  settings it could take several hours for the attacker to gather
  enough data to recover just a few characters of the password. This
  result was presented at the Fast Software Encryption 2007 conference.

  - CVE-2007-1362:

  Nicolas Derouet reported two problems with cookie handling in
  Mozilla clients.  Insufficient length checks could be use to exhaust
  browser memory and so to crash the browser or at least slow it done
  by a large degree.

  The second issue was that the cookie path and name values were not
  checked for the presence of the delimiter used for internal cookie
  storage, and if present this confused future interpretation of the
  cookie data. This is not considered to be exploitable.

  - CVE-2007-2869:

  Marcel repor ... 

  Description truncated, for more information please check the Reference URL";

tag_impact = "remote code execution";
tag_affected = "mozilla,MozillaFirefox,MozillaThunderbird on SUSE LINUX 10.1, openSUSE 10.2, SuSE Linux Enterprise Server 8, SUSE SLES 9, Novell Linux Desktop 9, Open Enterprise Server, Novell Linux POS 9, SUSE Linux Enterprise Desktop 10 SP1, SUSE Linux Enterprise Server 10 SP1";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.311180");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-1362", "CVE-2007-1558", "CVE-2007-1562", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-2869", "CVE-2007-2870", "CVE-2007-2871");
  script_name( "SuSE Update for mozilla,MozillaFirefox,MozillaThunderbird SUSE-SA:2007:036");

  script_tag(name:"summary", value:"Check for the Version of mozilla,MozillaFirefox,MozillaThunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "impact" , value : tag_impact);
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

if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.4~1.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.4~1.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~1.5.0.12~3.2", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations", rpm:"MozillaThunderbird-translations~1.5.0.12~3.2", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~1.1.2~1.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~1.1.2~1.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~1.1.2~1.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-mail", rpm:"seamonkey-mail~1.1.2~1.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-spellchecker", rpm:"seamonkey-spellchecker~1.1.2~1.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~1.1.2~1.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESSr8")
{

  if ((res = isrpmvuln(pkg:"mozilla", rpm:"mozilla~1.8_seamonkey_1.0.9~0.3", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-calendar", rpm:"mozilla-calendar~1.8_seamonkey_1.0.9~0.3", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-devel", rpm:"mozilla-devel~1.8_seamonkey_1.0.9~0.3", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-dom-inspector", rpm:"mozilla-dom-inspector~1.8_seamonkey_1.0.9~0.3", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-irc", rpm:"mozilla-irc~1.8_seamonkey_1.0.9~0.3", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-mail", rpm:"mozilla-mail~1.8_seamonkey_1.0.9~0.3", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-spellchecker", rpm:"mozilla-spellchecker~1.8_seamonkey_1.0.9~0.3", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-venkman", rpm:"mozilla-venkman~1.8_seamonkey_1.0.9~0.3", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xmlterm", rpm:"mozilla-xmlterm~1.8_seamonkey_1.0.9~0.3", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLPOS9")
{

  if ((res = isrpmvuln(pkg:"mozilla", rpm:"mozilla~1.8_seamonkey_1.0.9~1.2", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-cs", rpm:"mozilla-cs~1.8_seamonkey_1.0.4~0.5", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-deat", rpm:"mozilla-deat~1.8_seamonkey_1.0.4~0.5", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-devel", rpm:"mozilla-devel~1.8_seamonkey_1.0.9~1.2", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-dom-inspector", rpm:"mozilla-dom-inspector~1.8_seamonkey_1.0.9~1.2", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-hu", rpm:"mozilla-hu~1.80_seamonkey_1.0.4~3", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-irc", rpm:"mozilla-irc~1.8_seamonkey_1.0.9~1.2", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-mail", rpm:"mozilla-mail~1.8_seamonkey_1.0.9~1.2", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-venkman", rpm:"mozilla-venkman~1.8_seamonkey_1.0.9~1.2", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-lib64", rpm:"mozilla-lib64~1.6~0.9", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-calendar", rpm:"mozilla-calendar~1.8_seamonkey_1.0.9~1.2", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "OES")
{

  if ((res = isrpmvuln(pkg:"mozilla", rpm:"mozilla~1.8_seamonkey_1.0.9~1.2", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-cs", rpm:"mozilla-cs~1.8_seamonkey_1.0.4~0.5", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-deat", rpm:"mozilla-deat~1.8_seamonkey_1.0.4~0.5", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-devel", rpm:"mozilla-devel~1.8_seamonkey_1.0.9~1.2", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-dom-inspector", rpm:"mozilla-dom-inspector~1.8_seamonkey_1.0.9~1.2", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-hu", rpm:"mozilla-hu~1.80_seamonkey_1.0.4~3", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-irc", rpm:"mozilla-irc~1.8_seamonkey_1.0.9~1.2", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-mail", rpm:"mozilla-mail~1.8_seamonkey_1.0.9~1.2", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-venkman", rpm:"mozilla-venkman~1.8_seamonkey_1.0.9~1.2", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-lib64", rpm:"mozilla-lib64~1.6~0.9", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-calendar", rpm:"mozilla-calendar~1.8_seamonkey_1.0.9~1.2", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES9")
{

  if ((res = isrpmvuln(pkg:"mozilla", rpm:"mozilla~1.8_seamonkey_1.0.9~1.2", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-cs", rpm:"mozilla-cs~1.8_seamonkey_1.0.4~0.5", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-deat", rpm:"mozilla-deat~1.8_seamonkey_1.0.4~0.5", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-devel", rpm:"mozilla-devel~1.8_seamonkey_1.0.9~1.2", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-dom-inspector", rpm:"mozilla-dom-inspector~1.8_seamonkey_1.0.9~1.2", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-hu", rpm:"mozilla-hu~1.80_seamonkey_1.0.4~3", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-irc", rpm:"mozilla-irc~1.8_seamonkey_1.0.9~1.2", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-mail", rpm:"mozilla-mail~1.8_seamonkey_1.0.9~1.2", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-venkman", rpm:"mozilla-venkman~1.8_seamonkey_1.0.9~1.2", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-lib64", rpm:"mozilla-lib64~1.6~0.9", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-calendar", rpm:"mozilla-calendar~1.8_seamonkey_1.0.9~1.2", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "LES10SP1")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.4~1.5", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.4~1.5", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"mozilla", rpm:"mozilla~1.8_seamonkey_1.0.9~1.2", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-cs", rpm:"mozilla-cs~1.8_seamonkey_1.0.4~0.5", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-deat", rpm:"mozilla-deat~1.8_seamonkey_1.0.4~0.5", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-devel", rpm:"mozilla-devel~1.8_seamonkey_1.0.9~1.2", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-dom-inspector", rpm:"mozilla-dom-inspector~1.8_seamonkey_1.0.9~1.2", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-hu", rpm:"mozilla-hu~1.80_seamonkey_1.0.4~3", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-irc", rpm:"mozilla-irc~1.8_seamonkey_1.0.9~1.2", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-mail", rpm:"mozilla-mail~1.8_seamonkey_1.0.9~1.2", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-venkman", rpm:"mozilla-venkman~1.8_seamonkey_1.0.9~1.2", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-lib64", rpm:"mozilla-lib64~1.6~0.9", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-calendar", rpm:"mozilla-calendar~1.8_seamonkey_1.0.9~1.2", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"epiphany", rpm:"epiphany~1.2.10~0.6", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"epiphany-extensions", rpm:"epiphany-extensions~0.8.2~2.7", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~1.5.0.12~0.1", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~1.5.0.12~0.1", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP1")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.4~1.5", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.4~1.5", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~1.5.0.12~2.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations", rpm:"MozillaThunderbird-translations~1.5.0.12~2.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~1.0.9~1.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-calendar", rpm:"seamonkey-calendar~1.0.9~1.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~1.0.9~1.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~1.0.9~1.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-mail", rpm:"seamonkey-mail~1.0.9~1.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-spellchecker", rpm:"seamonkey-spellchecker~1.0.9~1.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~1.0.9~1.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
