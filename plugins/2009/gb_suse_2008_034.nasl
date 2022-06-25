###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2008_034.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for MozillaFirefox SUSE-SA:2008:034
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
tag_insight = "Mozilla Firefox was updated to version 2.0.0.15, fixing various bugs
  including following security bugs.

  MFSA 2008-21:
  Mozilla developers identified and fixed several stability bugs in the
  browser engine used in Firefox and other Mozilla-based products. Some
  of these crashes showed evidence of memory corruption under certain
  circumstances and we presume that with enough effort at least some
  of these could be exploited to run arbitrary code.

  MFSA 2008-22:
  Mozilla contributor moz_bug_r_a4 submitted a set of vulnerabilities
  which allow scripts from one document to be executed in the context
  of a different document. These vulnerabilities could be used by an
  attacker to violate the same-origin policy and perform an XSS attack.

  MFSA 2008-23:
  Security researcher Collin Jackson reported a series of vulnerabilities
  which allow JavaScript to be injected into signed JARs and executed
  under the context of the JAR's signer. This could allow an attacker
  to run JavaScript in a victim's browser with the privileges of a
  different website, provided the attacker possesses a JAR signed by
  the other website.

  MFSA 2008-24:
  Mozilla contributor moz_bug_r_a4 reported a vulnerability that
  allowed non-privileged XUL documents to load chrome scripts from
  the fastload file.  This could allow an attacker to run arbitrary
  JavaScript code with chrome privileges.

  MFSA 2008-25:
  Mozilla contributor moz_bug_r_a4 reported a vulnerability which allows
  arbitrary JavaScript to be executed with chrome privileges. The
  privilege escalation was possible because JavaScript loaded via
  mozIJSSubScriptLoader.loadSubScript() was not using XPCNativeWrappers
  when accessing content. This could allow an attacker to overwrite
  trusted objects with arbitrary code which would be executed with
  chrome privileges when the trusted objects were called by the browser.

  MFSA 2008-27:
  Opera developer Claudio Santambrogio reported a vulnerability which
  allows malicious content to force the browser into uploading local
  files to the remote server. This could be used by an attacker to
  steal arbitrary files from a victim's computer.

  MFSA 2008-28:
  Security researcher Gregory Fleischer reported a vulnerability
  in the way Mozilla indicates the origi ... 

  Description truncated, for more information please check the Reference URL";

tag_impact = "remote code execution";
tag_affected = "MozillaFirefox on openSUSE 10.2, openSUSE 10.3, SUSE Linux Enterprise Desktop 10 SP1, SUSE Linux Enterprise Server 10 SP1, SUSE Linux Enterprise Desktop 10 SP2, SUSE Linux Enterprise 10 SP2 DEBUGINFO, SUSE Linux Enterprise Server 10 SP2";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.307368");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800", "CVE-2008-2801", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2805", "CVE-2008-2806", "CVE-2008-2807", "CVE-2008-2808", "CVE-2008-2809", "CVE-2008-2810", "CVE-2008-2811");
  script_name( "SuSE Update for MozillaFirefox SUSE-SA:2008:034");

  script_tag(name:"summary", value:"Check for the Version of MozillaFirefox");
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

if(release == "openSUSE10.3")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.15~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.15~0.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.15~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.15~0.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "LES10SP1")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.15~0.2.3", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.15~0.2.3", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.15~0.3", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.15~0.3", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~2.0.0.15~0.3", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "LES10SP2")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.15~0.2.3", rls:"LES10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.15~0.2.3", rls:"LES10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.15~0.3", rls:"LES10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.15~0.3", rls:"LES10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~2.0.0.15~0.3", rls:"LES10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLEDe10SP2")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.15~0.2.3", rls:"SLEDe10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.15~0.2.3", rls:"SLEDe10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.15~0.3", rls:"SLEDe10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.15~0.3", rls:"SLEDe10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~2.0.0.15~0.3", rls:"SLEDe10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP2")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.15~0.2.3", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.15~0.2.3", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.15~0.3", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.15~0.3", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~2.0.0.15~0.3", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP1")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.15~0.2.3", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.15~0.2.3", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~2.0.0.15~0.3", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~2.0.0.15~0.3", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~2.0.0.15~0.3", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
