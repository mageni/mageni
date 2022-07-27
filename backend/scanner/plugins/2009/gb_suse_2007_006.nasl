###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_006.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for mozilla SUSE-SA:2007:006
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
tag_insight = "A number of security issues have been fixed in the Mozilla browser
  suite, which could be used by remote attackers to gain privileges,
  access to confidential information or cause denial of service attacks.

  Since the Mozilla Suite 1.7 branch is no longer maintained this
  update most of our older products to use the Mozilla Seamonkey Suite
  version 1.0.7.

  Security issues we fixed (compared from last seamonkey update round
  only) are listed below. More Details regarding the problems can be
  found on this page:
  http://www.mozilla.org/projects/security/known-vulnerabilities.html

  The updated packages includes fixes for the following security problems:
  MFSA 2006-68: Crashes with evidence of memory corruption
  were fixed in the layout engine.
  MFSA 2006-68: Crashes with evidence of memory corruption
  were fixed in the javascript engine.
  MFSA 2006-68: Crashes regarding floating point usage
  were fixed. Linux is not affected.
  MFSA 2006-70: A privilege escalation using a watch
  point was fixed.
  MFSA 2006-71: A LiveConnect crash finalizing JS objects
  was fixed.
  MFSA 2006-72: A XSS problem caused by setting img.src
  to javascript: URI was fixed.
  MFSA 2006-73: A Mozilla SVG Processing Remote Code
  Execution was fixed.
  MFSA 2006-74: Some Mail header processing heap overflows
  were fixed.
  MFSA 2006-75: The RSS Feed-preview referrer leak
  was fixed.
  MFSA 2006-76: A XSS problem using outer window's Function
  object was fixed.

  Problems with these packages we could not fix yet:

  - On SUSE Linux Desktop 1.0 the upgrade was not possible yet due
  to library inter-dependencies problems between Mozilla and GTK+.

  We recommend deinstalling mozilla on this product.

  - The SUSE Linux Enterprise Server 8 update has shown regressions
  in flash and java plugin handling which we are investigating.

  - On SUSE Linux 10.0 epiphany stops working for still unknown reasons.

  We are investigating this and recommend using mozilla or
  MozillaFirefox directly instead.";

tag_impact = "remote denial of service";
tag_affected = "mozilla on Novell Linux Desktop 9, Novell Linux POS 9, Open Enterprise Server, SUSE LINUX 10.1, SUSE SLES 9";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.307197");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2006-6497", "CVE-2006-6498", "CVE-2006-6499", "CVE-2006-6500", "CVE-2006-6501", "CVE-2006-6502", "CVE-2006-6503", "CVE-2006-6504", "CVE-2006-6505", "CVE-2006-6506", "CVE-2006-6507");
  script_name( "SuSE Update for mozilla SUSE-SA:2007:006");

  script_tag(name:"summary", value:"Check for the Version of mozilla");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms");
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

if(release == "OES")
{

  if ((res = isrpmvuln(pkg:"mozilla", rpm:"mozilla~1.8_seamonkey_1.0.7~1.1", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-cs", rpm:"mozilla-cs~1.8_seamonkey_1.0.4~0.3", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-deat", rpm:"mozilla-deat~1.8_seamonkey_1.0.4~0.3", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-devel", rpm:"mozilla-devel~1.8_seamonkey_1.0.7~1.1", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-dom-inspector", rpm:"mozilla-dom-inspector~1.8_seamonkey_1.0.7~1.1", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-hu", rpm:"mozilla-hu~1.80_seamonkey_1.0.4~0.1", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-irc", rpm:"mozilla-irc~1.8_seamonkey_1.0.7~1.1", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-lib64", rpm:"mozilla-lib64~1.6~0.7", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-mail", rpm:"mozilla-mail~1.8_seamonkey_1.0.7~1.1", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-venkman", rpm:"mozilla-venkman~1.8_seamonkey_1.0.7~1.1", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-calendar", rpm:"mozilla-calendar~1.8_seamonkey_1.0.7~1.1", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES9")
{

  if ((res = isrpmvuln(pkg:"mozilla", rpm:"mozilla~1.8_seamonkey_1.0.7~1.1", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-cs", rpm:"mozilla-cs~1.8_seamonkey_1.0.4~0.3", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-deat", rpm:"mozilla-deat~1.8_seamonkey_1.0.4~0.3", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-devel", rpm:"mozilla-devel~1.8_seamonkey_1.0.7~1.1", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-dom-inspector", rpm:"mozilla-dom-inspector~1.8_seamonkey_1.0.7~1.1", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-hu", rpm:"mozilla-hu~1.80_seamonkey_1.0.4~0.1", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-irc", rpm:"mozilla-irc~1.8_seamonkey_1.0.7~1.1", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-lib64", rpm:"mozilla-lib64~1.6~0.7", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-mail", rpm:"mozilla-mail~1.8_seamonkey_1.0.7~1.1", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-venkman", rpm:"mozilla-venkman~1.8_seamonkey_1.0.7~1.1", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-calendar", rpm:"mozilla-calendar~1.8_seamonkey_1.0.7~1.1", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"epiphany", rpm:"epiphany~1.2.10~0.4", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"epiphany-doc", rpm:"epiphany-doc~1.2.10~0.4", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"epiphany-extensions", rpm:"epiphany-extensions~0.8.2~2.5", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla", rpm:"mozilla~1.8_seamonkey_1.0.7~1.1", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-cs", rpm:"mozilla-cs~1.8_seamonkey_1.0.4~0.3", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-deat", rpm:"mozilla-deat~1.8_seamonkey_1.0.4~0.3", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-devel", rpm:"mozilla-devel~1.8_seamonkey_1.0.7~1.1", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-dom-inspector", rpm:"mozilla-dom-inspector~1.8_seamonkey_1.0.7~1.1", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-hu", rpm:"mozilla-hu~1.80_seamonkey_1.0.4~0.1", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-irc", rpm:"mozilla-irc~1.8_seamonkey_1.0.7~1.1", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-lib64", rpm:"mozilla-lib64~1.6~0.7", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-mail", rpm:"mozilla-mail~1.8_seamonkey_1.0.7~1.1", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-venkman", rpm:"mozilla-venkman~1.8_seamonkey_1.0.7~1.1", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-calendar", rpm:"mozilla-calendar~1.8_seamonkey_1.0.7~1.1", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~1.0.7~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-calendar", rpm:"seamonkey-calendar~1.0.7~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~1.0.7~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~1.0.7~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-mail", rpm:"seamonkey-mail~1.0.7~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-spellchecker", rpm:"seamonkey-spellchecker~1.0.7~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~1.0.7~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLPOS9")
{

  if ((res = isrpmvuln(pkg:"mozilla", rpm:"mozilla~1.8_seamonkey_1.0.7~1.1", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-cs", rpm:"mozilla-cs~1.8_seamonkey_1.0.4~0.3", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-deat", rpm:"mozilla-deat~1.8_seamonkey_1.0.4~0.3", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-devel", rpm:"mozilla-devel~1.8_seamonkey_1.0.7~1.1", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-dom-inspector", rpm:"mozilla-dom-inspector~1.8_seamonkey_1.0.7~1.1", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-hu", rpm:"mozilla-hu~1.80_seamonkey_1.0.4~0.1", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-irc", rpm:"mozilla-irc~1.8_seamonkey_1.0.7~1.1", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-lib64", rpm:"mozilla-lib64~1.6~0.7", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-mail", rpm:"mozilla-mail~1.8_seamonkey_1.0.7~1.1", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-venkman", rpm:"mozilla-venkman~1.8_seamonkey_1.0.7~1.1", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-calendar", rpm:"mozilla-calendar~1.8_seamonkey_1.0.7~1.1", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
