###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for MozillaFirefox,MozillaThunderbird,seamonkey SUSE-SA:2010:032
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
tag_insight = "Various security issues have been found in the Mozilla suite, and
  the various browsers have been updated to fix these issues.

  Mozilla Firefox was brought to the 3.5.11 security release.
  Mozilla Firefox on openSUSE 11.3 was brought to the 3.6.8 security release.
  Mozilla Thunderbird was brought to the 3.0.11 release on openSUSE
  11.2 and 11.3.
  Mozilla Seamonkey was brought to the 2.0.6 release on openSUSE 11.2
  and 11.3.
  Mozilla XULRunner was brought to 1.9.1.11 and 1.9.2.8 respectively.

  The updates fix following security bugs:
  CVE-2010-1212: Mozilla developers
  identified and fixed several memory safety bugs in the browser engine
  used in Firefox and other Mozilla-based products. Some of these bugs
  showed evidence of memory corruption under certain circumstances,
  and we presume that with enough effort at least some of these could
  be exploited to run arbitrary code.  Jesse Ruderman, Ehsan Akhgari,
  Mats Palmgren, Igor Bukanov, Gary Kwong, Tobias Markus and Daniel
  Holbert reported memory safety problems that affected Firefox 3.6
  and Firefox 3.5.

  CVE-2010-1208: Security researcher regenrecht reported
  via TippingPoint's Zero Day Initiative an error in the DOM attribute
  cloning routine where under certain circumstances an event attribute
  node can be deleted while another object still contains a reference
  to it. This reference could subsequently be accessed, potentially
  causing the execution of attacker controlled memory.

  CVE-2010-1209: Security researcher regenrecht
  reported via TippingPoint's Zero Day Initiative an error in Mozilla's
  implementation of NodeIterator in which a malicious NodeFilter could
  be created which would detach nodes from the DOM tree while it was
  being traversed. The use of a detached and subsequently deleted node
  could result in the execution of attacker-controlled memory.

  CVE-2010-1214: Security researcher J23 reported via
  TippingPoint's Zero Day Initiative an error in the code used to store
  the names and values of plugin parameter elements. A malicious page
  could embed plugin content containing a very large number of parameter
  elements which would cause an overflow in the integer value counting
  them. This integer is later used in allocating a memory buffer used
  to store the plugin parameters. Under such conditions, too small a
  buffer would be created and attacker-controlled data could be written
  past the end of the buffer, potentially resulting in code execution.

  CVE-2010-1215: Mozilla security researcher moz_bug_r_a4
  r ... 

  Description truncated, for more information please check the Reference URL";
tag_solution = "Please Install the Updated Packages.";

tag_impact = "remote code execution";
tag_affected = "MozillaFirefox,MozillaThunderbird,seamonkey on openSUSE 11.1, openSUSE 11.2";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.314908");
  script_version("$Revision: 8258 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-29 08:28:57 +0100 (Fri, 29 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-08-06 10:34:50 +0200 (Fri, 06 Aug 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0654", "CVE-2010-1205", "CVE-2010-1206", "CVE-2010-1207", "CVE-2010-1208", "CVE-2010-1209", "CVE-2010-1210", "CVE-2010-1211", "CVE-2010-1212", "CVE-2010-1213", "CVE-2010-1214", "CVE-2010-1215", "CVE-2010-2751", "CVE-2010-2752", "CVE-2010-2753", "CVE-2010-2754", "CVE-2010-2755");
  script_name("SuSE Update for MozillaFirefox,MozillaThunderbird,seamonkey SUSE-SA:2010:032");

  script_tag(name: "summary" , value: "Check for the Version of MozillaFirefox,MozillaThunderbird,seamonkey");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

if(release == "openSUSE11.1")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~3.5.11~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~3.5.11~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~3.5.11~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~3.5.11~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner191", rpm:"mozilla-xulrunner191~1.9.1.11~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner191-devel", rpm:"mozilla-xulrunner191-devel~1.9.1.11~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner191-gnomevfs", rpm:"mozilla-xulrunner191-gnomevfs~1.9.1.11~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner191-translations-common", rpm:"mozilla-xulrunner191-translations-common~1.9.1.11~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner191-translations-other", rpm:"mozilla-xulrunner191-translations-other~1.9.1.11~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-xpcom191", rpm:"python-xpcom191~1.9.1.11~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner191-32bit", rpm:"mozilla-xulrunner191-32bit~1.9.1.11~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner191-gnomevfs-32bit", rpm:"mozilla-xulrunner191-gnomevfs-32bit~1.9.1.11~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE11.2")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~3.5.11~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~3.5.11~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~3.5.11~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~3.5.11~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~3.0.6~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~3.0.6~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~3.0.6~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~3.0.6~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"enigmail", rpm:"enigmail~1.0.1~1.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner191", rpm:"mozilla-xulrunner191~1.9.1.11~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner191-devel", rpm:"mozilla-xulrunner191-devel~1.9.1.11~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner191-gnomevfs", rpm:"mozilla-xulrunner191-gnomevfs~1.9.1.11~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner191-translations-common", rpm:"mozilla-xulrunner191-translations-common~1.9.1.11~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner191-translations-other", rpm:"mozilla-xulrunner191-translations-other~1.9.1.11~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-xpcom191", rpm:"python-xpcom191~1.9.1.11~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.0.6~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~2.0.6~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~2.0.6~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~2.0.6~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner191-32bit", rpm:"mozilla-xulrunner191-32bit~1.9.1.11~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-xulrunner191-gnomevfs-32bit", rpm:"mozilla-xulrunner191-gnomevfs-32bit~1.9.1.11~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
