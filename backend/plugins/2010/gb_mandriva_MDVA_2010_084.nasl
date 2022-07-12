###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for x11-driver-video-ati MDVA-2010:084 (x11-driver-video-ati)
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
tag_affected = "x11-driver-video-ati on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64";
tag_insight = "There was a bug in the ATI X1200 driver, making it show very frequent
  screen corruption. This update fixes the issue.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-02/msg00064.php");
  script_oid("1.3.6.1.4.1.25623.1.0.314598");
  script_version("$Revision: 8228 $");
  script_cve_id("CVE-2009-2409", "CVE-2009-3555", "CVE-2009-3728", "CVE-2009-3869",
                "CVE-2009-3871", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875",
                "CVE-2009-3876", "CVE-2009-3877", "CVE-2009-3879", "CVE-2009-3880",
                "CVE-2009-3881", "CVE-2009-3882", "CVE-2009-3883", "CVE-2009-3884",
                "CVE-2009-3885", "CVE-2010-0082", "CVE-2010-0084", "CVE-2010-0085",
                "CVE-2010-0088", "CVE-2010-0091", "CVE-2010-0092", "CVE-2010-0093",
                "CVE-2010-0094", "CVE-2010-0095", "CVE-2010-0837", "CVE-2010-0838",
                "CVE-2010-0840", "CVE-2010-0845", "CVE-2010-0847", "CVE-2010-0848");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 08:29:52 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-03-02 08:46:47 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVA", value: "2010:084");
  script_name("Mandriva Update for x11-driver-video-ati MDVA-2010:084 (x11-driver-video-ati)");

  script_tag(name: "summary" , value: "Check for the Version of x11-driver-video-ati");
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

  if ((res = isrpmvuln(pkg:"x11-driver-video-ati", rpm:"x11-driver-video-ati~6.12.4~1.2mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
