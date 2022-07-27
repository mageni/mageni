###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2008_001.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for opera SUSE-SA:2008:001
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
tag_insight = "Opera released version 9.25 of their browser to fix various security
  problems:

  CVE-2007-6520: Fixed an issue where plug-ins could be used to allow
  cross domain scripting, as reported by David Bloom. Details will be
  disclosed at a later date.

  CVE-2007-6521: Fixed an issue with TLS certificates that could
  be used to execute arbitrary code, as reported by Alexander Klink
  (Cynops GmbH). Details will be disclosed at a later date.

  CVE-2007-6522: Rich text editing can no longer be used to allow cross
  domain scripting, as reported by David Bloom. See our advisory.

  CVE-2007-6523: Fixed a problem where malformed BMP files could cause
  Opera to temporarily freeze.

  CVE-2007-6524: Prevented bitmaps from revealing random data from
  memory, as reported by Gynvael Coldwind. Details will be disclosed
  at a later date.";

tag_impact = "remote code execution";
tag_affected = "opera on SUSE LINUX 10.1, openSUSE 10.2, openSUSE 10.3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.311498");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-6520", "CVE-2007-6521", "CVE-2007-6522", "CVE-2007-6523", "CVE-2007-6524");
  script_name( "SuSE Update for opera SUSE-SA:2008:001");

  script_tag(name:"summary", value:"Check for the Version of opera");
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

  if ((res = isrpmvuln(pkg:"opera", rpm:"opera~9.25~1.1", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"opera", rpm:"opera~9.25~1.1", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"opera", rpm:"opera~9.25~1.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
