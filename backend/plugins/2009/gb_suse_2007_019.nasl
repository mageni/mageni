###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_019.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for MozillaFirefox,seamonkey SUSE-SA:2007:019
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
tag_insight = "The Mozilla Firefox web browser was updated to security update version
  1.5.0.10 on older products and Mozilla Firefox to version 2.0.0.2 on
  openSUSE 10.2 to fix various security issues.

  Updates for the Mozilla seamonkey suite before 10.2, Mozilla Suite
  and Mozilla Thunderbird are still pending.

  Full details can be found on:
  http://www.mozilla.org/projects/security/known-vulnerabilities.html

  - MFSA 2007-01: As part of the Firefox 2.0.0.2  and 1.5.0.10 update
  releases several bugs were fixed to improve the stability of the
  browser. Some of these were crashes that showed evidence of memory
  corruption and we presume that with enough effort at least some of
  these could be exploited to run arbitrary code. These fixes affected
  the layout engine CVE-2007-0776
  and javascript engine CVE-2007-0777.

  - MFSA 2007-02: Various enhancements were done to make XSS exploits
  against websites less effective. These included fixes for invalid
  trailing characters CVE-2007-0995, child frame character set
  inheritance CVE-2006-6077,
  and the Adobe Reader universal XSS problem.

  - CVE-2007-0778: AAd reported a potential disk cache
  collision that could be exploited by remote attackers to steal
  confidential data or execute code.

  - CVE-2007-0779: David Eckel reported that browser UI
  elements--such as the host name and security indicators--could be
  spoofed by using a large, mostly transparent, custom cursor and
  adjusting the CSS3 hot-spot property so that the visible part of
  the cursor floated outside the browser content area.

  - MFSA 2007-05: Manually opening blocked popups could be exploited by
  remote attackers to allow XSS attacks CVE-2007-0780 or to execute
  code in local files CVE-2007-0800.

  - MFSA 2007-06:
  Two buffer overflows were found in the NSS handling of Mozilla.

  CVE-2007-0008: SSL clients such as Firefox and Thunderbird can suffer
  a buffer overflow if a malicious server presents a certificate
  with a public key that is too small to encrypt the entire &quot;Master
  Secret&quot;. Exploiting this overflow appears to be unreliable but
  possible if the SSLv2 protocol is enabled.

  CVE-2007-0009: Servers that use NSS for the SSLv2 protocol can
  be exploited by a client that presents a &quot;Client Master Key&quo ... 

  Description truncated, for more information please check the Reference URL";

tag_impact = "remote code execution";
tag_affected = "MozillaFirefox,seamonkey on SUSE LINUX 10.1, openSUSE 10.2, Novell Linux Desktop 9, SUSE SLED 10, SUSE SLES 10";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.306310");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2006-6077", "CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0775", "CVE-2007-0776", "CVE-2007-0777", "CVE-2007-0778", "CVE-2007-0779", "CVE-2007-0780", "CVE-2007-0800", "CVE-2007-0981", "CVE-2007-0994", "CVE-2007-0995", "CVE-2007-0996", "CVE-2007-1092");
  script_name( "SuSE Update for MozillaFirefox,seamonkey SUSE-SA:2007:019");

  script_tag(name:"summary", value:"Check for the Version of MozillaFirefox,seamonkey");
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

if(release == "SLED10")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~1.5.0.10~0.2", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~1.5.0.10~0.2", rls:"SLED10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.2~1.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.2~1.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~1.1.1~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~1.1.1~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~1.1.1~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-mail", rpm:"seamonkey-mail~1.1.1~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-spellchecker", rpm:"seamonkey-spellchecker~1.1.1~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~1.1.1~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES10")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~1.5.0.10~0.2", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~1.5.0.10~0.2", rls:"SLES10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~1.5.0.10~0.2", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~1.5.0.10~0.2", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~1.5.0.10~0.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~1.5.0.10~0.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
