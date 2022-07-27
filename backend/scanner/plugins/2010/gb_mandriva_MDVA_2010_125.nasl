###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for ldetect-lst MDVA-2010:125 (ldetect-lst)
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
tag_affected = "ldetect-lst on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64";
tag_insight = "Update of ldetect-lst to add the support of new Intel GPU: Atom
  Pineview G, Atom Pineview GM, Intel B43 and Intel Core i3/i5 IGP. Also
  update the monitor DB to add two new Samsung SyncMaster devices.";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-04/msg00034.php");
  script_oid("1.3.6.1.4.1.25623.1.0.313685");
  script_version("$Revision: 8495 $");
  script_cve_id("CVE-2008-5913", "CVE-2010-1125", "CVE-2010-1196", "CVE-2010-1197",
                "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1202",
                "CVE-2010-1203");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-29 13:13:58 +0200 (Thu, 29 Apr 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVA", value: "2010:125");
  script_name("Mandriva Update for ldetect-lst MDVA-2010:125 (ldetect-lst)");

  script_tag(name: "summary" , value: "Check for the Version of ldetect-lst");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"ldetect-lst", rpm:"ldetect-lst~0.1.279.1~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ldetect-lst-devel", rpm:"ldetect-lst-devel~0.1.279.1~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
