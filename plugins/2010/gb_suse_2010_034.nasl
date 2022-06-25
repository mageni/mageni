###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for flash-player SUSE-SA:2010:034
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
tag_impact = "remote code execution";
tag_affected = "flash-player on openSUSE 11.1, openSUSE 11.2";
tag_insight = "Flash Player was updated to version 10.1.82.76 fixing several critical
  security issues:
  - CVE-2010-0209: CVSS v2 Base Score: 9.3: Code Injection (CWE-94)
  Details unknown.
  - CVE-2010-2188: CVSS v2 Base Score: 6.8: Buffer Errors (CWE-119)
  Allowed attackers to cause a memory corruption or possibly even
  execute arbitrary code by calling the ActionScript native object 2200
  connect method multiple times with different arguments.
  - CVE-2010-2213: CVSS v2 Base Score: 9.3: Code Injection (CWE-94)
  Details unknown.
  - CVE-2010-2214: CVSS v2 Base Score: 9.3: Code Injection (CWE-94)
  Details unknown.
  - CVE2010-2215: CVSS v2 Base Score: 4.3: Other (CWE-Other)
  Allowed an attack related to so called &quot;click-jacking&quot;.
  - CVE-2010-2216: CVSS v2 Base Score: 9.3: Code Injection (CWE-94)
  Details unknown.";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.313853");
  script_version("$Revision: 8269 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-02 08:28:22 +0100 (Tue, 02 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-16 14:28:27 +0200 (Mon, 16 Aug 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0209", "CVE-2010-2188", "CVE-2010-2213", "CVE-2010-2214", "CVE-2010-2215", "CVE-2010-2216");
  script_name("SuSE Update for flash-player SUSE-SA:2010:034");

  script_tag(name: "summary" , value: "Check for the Version of flash-player");
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

  if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~10.1.82.76~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE11.2")
{

  if ((res = isrpmvuln(pkg:"flash-player", rpm:"flash-player~10.1.82.76~0.1.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
