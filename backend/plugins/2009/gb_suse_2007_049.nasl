###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_049.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for MozillaFirefox,MozillaThunderbird,Seamonkey SUSE-SA:2007:049
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
tag_insight = "Various security problems were found and fixed
  in Mozilla Firefox, Thunderbird and Seamonkey.

  Some of them received version updates,  but the Firefox and Thunderbird
  1.5.0.12 versions received backports.

  The updates have been released over the last 10 days and the last
  were released today.

  Following security problems were fixed:
  - MFSA 2007-18: Crashes with evidence of memory corruption

  The usual collection of stability fixes for crashes that look suspicious but
  haven't been proven to be exploitable.

  25 were in the browser engine, reported by  Mozilla developers and community
  members Bernd Mielke, Boris Zbarsky,  David Baron, Daniel Veditz, Jesse
  Ruderman, Lukas Loehrer, Martijn Wargers, Mats Palmgren, Olli Pettay, Paul
  Nickerson,and  Vladimir Sukhoy CVE-2007-3734

  7 were in the JavaScript engine reported by Asaf Romano, Jesse Ruderman, Igor
  Bukanov CVE-2007-3735

  - CVE-2007-3736: XSS using addEventListener and setTimeout

  moz_bug_r_a4 reported that scripts could be injected into another site's
  context by exploiting a timing issue using addEventLstener or setTimeout.

  - CVE-2007-3089: frame spoofing

  Ronen Zilberman and Michal Zalewski both reported that it was possible to
  exploit a timing issue to inject content into about:blank frames in a page.

  - CVE-2007-3737:  Privilege escalation using an event
  handler attached to an element not in the document

  Reported by moz_bug_r_a4.

  - CVE-2007-3285: File type confusion due to %00 in name

  Ronald van den Heetkamp reported that a filename URL containing %00 (encoded
  null) can cause Firefox to interpret the file extension differently than the
  underlying Windows operating system potentially leading to unsafe actions such
  as running a program.

  - CVE-2007-3670: Remote code execution by launching Firefox from Internet Explorer

  Greg MacManus of iDefense and Billy Rios of Verisign independently reported
  that links containing a quote (&quot;) character could be used in Internet Explorer
  to launch registered URL Protocol handlers with extra command-line parameters.
  Firefox and Thunderbird are among those which can be launched, and both support
  a &quot;-chrome&quot; option that could be used to run malware.

  This problem does not affect Linux.

  - CVE-2007-3656: unauthorized access to wyciwyg:// documents

  Michal Zalewski reported that it was possible to bypass the same-origin checks
  and read from cached (wyciwyg) documents

  Description truncated, for more information please check the Reference URL.";

tag_impact = "remote code execution";
tag_affected = "MozillaFirefox,MozillaThunderbird,Seamonkey on SUSE LINUX 10.1, openSUSE 10.2, SuSE Linux Enterprise Server 8, SUSE SLES 9, Novell Linux Desktop 9, Open Enterprise Server, Novell Linux POS 9, SUSE Linux Enterprise Desktop 10 SP1, SUSE Linux Enterprise Server 10 SP1";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.306706");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-3089", "CVE-2007-3285", "CVE-2007-3656", "CVE-2007-3670", "CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3737", "CVE-2007-3738");
  script_name( "SuSE Update for MozillaFirefox,MozillaThunderbird,Seamonkey SUSE-SA:2007:049");

  script_tag(name:"summary", value:"Check for the Version of MozillaFirefox,MozillaThunderbird,Seamonkey");
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

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.5~1.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.5~1.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~1.5.0.12~3.4", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations", rpm:"MozillaThunderbird-translations~1.5.0.12~3.4", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~1.1.3~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~1.1.3~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~1.1.3~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-mail", rpm:"seamonkey-mail~1.1.3~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-spellchecker", rpm:"seamonkey-spellchecker~1.1.3~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~1.1.3~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESSr8")
{

  if ((res = isrpmvuln(pkg:"mozilla", rpm:"mozilla~1.8_seamonkey_1.0.9~0.10", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-calendar", rpm:"mozilla-calendar~1.8_seamonkey_1.0.9~0.10", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-devel", rpm:"mozilla-devel~1.8_seamonkey_1.0.9~0.10", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-dom-inspector", rpm:"mozilla-dom-inspector~1.8_seamonkey_1.0.9~0.10", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-irc", rpm:"mozilla-irc~1.8_seamonkey_1.0.9~0.10", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-mail", rpm:"mozilla-mail~1.8_seamonkey_1.0.9~0.10", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-spellchecker", rpm:"mozilla-spellchecker~1.8_seamonkey_1.0.9~0.10", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-venkman", rpm:"mozilla-venkman~1.8_seamonkey_1.0.9~0.10", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xmlterm", rpm:"mozilla-xmlterm~1.8_seamonkey_1.0.9~0.10", rls:"SLESSr8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLPOS9")
{

  if ((res = isrpmvuln(pkg:"mozilla", rpm:"mozilla~1.8_seamonkey_1.0.9~1.4", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-cs", rpm:"mozilla-cs~1.8_seamonkey_1.0.4~0.6", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-deat", rpm:"mozilla-deat~1.8_seamonkey_1.0.4~0.6", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-devel", rpm:"mozilla-devel~1.8_seamonkey_1.0.9~1.4", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-dom-inspector", rpm:"mozilla-dom-inspector~1.8_seamonkey_1.0.9~1.4", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-hu", rpm:"mozilla-hu~1.80_seamonkey_1.0.4~4", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-irc", rpm:"mozilla-irc~1.8_seamonkey_1.0.9~1.4", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-mail", rpm:"mozilla-mail~1.8_seamonkey_1.0.9~1.4", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-venkman", rpm:"mozilla-venkman~1.8_seamonkey_1.0.9~1.4", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-lib64", rpm:"mozilla-lib64~1.6~0.10", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-calendar", rpm:"mozilla-calendar~1.8_seamonkey_1.0.9~1.4", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "OES")
{

  if ((res = isrpmvuln(pkg:"mozilla", rpm:"mozilla~1.8_seamonkey_1.0.9~1.4", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-cs", rpm:"mozilla-cs~1.8_seamonkey_1.0.4~0.6", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-deat", rpm:"mozilla-deat~1.8_seamonkey_1.0.4~0.6", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-devel", rpm:"mozilla-devel~1.8_seamonkey_1.0.9~1.4", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-dom-inspector", rpm:"mozilla-dom-inspector~1.8_seamonkey_1.0.9~1.4", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-hu", rpm:"mozilla-hu~1.80_seamonkey_1.0.4~4", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-irc", rpm:"mozilla-irc~1.8_seamonkey_1.0.9~1.4", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-mail", rpm:"mozilla-mail~1.8_seamonkey_1.0.9~1.4", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-venkman", rpm:"mozilla-venkman~1.8_seamonkey_1.0.9~1.4", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-lib64", rpm:"mozilla-lib64~1.6~0.10", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-calendar", rpm:"mozilla-calendar~1.8_seamonkey_1.0.9~1.4", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES9")
{

  if ((res = isrpmvuln(pkg:"mozilla", rpm:"mozilla~1.8_seamonkey_1.0.9~1.4", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-cs", rpm:"mozilla-cs~1.8_seamonkey_1.0.4~0.6", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-deat", rpm:"mozilla-deat~1.8_seamonkey_1.0.4~0.6", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-devel", rpm:"mozilla-devel~1.8_seamonkey_1.0.9~1.4", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-dom-inspector", rpm:"mozilla-dom-inspector~1.8_seamonkey_1.0.9~1.4", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-hu", rpm:"mozilla-hu~1.80_seamonkey_1.0.4~4", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-irc", rpm:"mozilla-irc~1.8_seamonkey_1.0.9~1.4", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-mail", rpm:"mozilla-mail~1.8_seamonkey_1.0.9~1.4", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-venkman", rpm:"mozilla-venkman~1.8_seamonkey_1.0.9~1.4", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-lib64", rpm:"mozilla-lib64~1.6~0.10", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-calendar", rpm:"mozilla-calendar~1.8_seamonkey_1.0.9~1.4", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "LES10SP1")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.5~1.2", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.5~1.2", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"mozilla", rpm:"mozilla~1.8_seamonkey_1.0.9~1.4", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-cs", rpm:"mozilla-cs~1.8_seamonkey_1.0.4~0.6", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-deat", rpm:"mozilla-deat~1.8_seamonkey_1.0.4~0.6", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-devel", rpm:"mozilla-devel~1.8_seamonkey_1.0.9~1.4", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-dom-inspector", rpm:"mozilla-dom-inspector~1.8_seamonkey_1.0.9~1.4", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-hu", rpm:"mozilla-hu~1.80_seamonkey_1.0.4~4", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-irc", rpm:"mozilla-irc~1.8_seamonkey_1.0.9~1.4", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-mail", rpm:"mozilla-mail~1.8_seamonkey_1.0.9~1.4", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-venkman", rpm:"mozilla-venkman~1.8_seamonkey_1.0.9~1.4", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-lib64", rpm:"mozilla-lib64~1.6~0.10", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-calendar", rpm:"mozilla-calendar~1.8_seamonkey_1.0.9~1.4", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~1.5.0.12~0.3", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~1.5.0.12~0.3", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP1")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.5~1.2", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.5~1.2", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.5~1.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.5~1.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~1.0.9~1.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-calendar", rpm:"seamonkey-calendar~1.0.9~1.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~1.0.9~1.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~1.0.9~1.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-mail", rpm:"seamonkey-mail~1.0.9~1.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-spellchecker", rpm:"seamonkey-spellchecker~1.0.9~1.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~1.0.9~1.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
