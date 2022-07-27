###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for kernel FEDORA-2010-18983
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
tag_affected = "kernel on Fedora 13";
tag_insight = "The kernel package contains the Linux kernel (vmlinuz), the core of any
  Linux operating system.  The kernel handles the basic functions
  of the operating system: memory allocation, process allocation, device
  input and output, etc.";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-December/052513.html");
  script_oid("1.3.6.1.4.1.25623.1.0.315112");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-12-28 07:11:56 +0100 (Tue, 28 Dec 2010)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2010-18983");
  script_cve_id("CVE-2010-4157", "CVE-2010-4158", "CVE-2010-3874", "CVE-2010-4162", "CVE-2010-4249", "CVE-2010-2962", "CVE-2010-2963", "CVE-2010-3698", "CVE-2010-3705", "CVE-2010-3442", "CVE-2010-4258", "CVE-2010-4169", "CVE-2010-4073", "CVE-2010-4072", "CVE-2010-3880", "CVE-2010-4082", "CVE-2010-3904", "CVE-2010-3432", "CVE-2010-3079", "CVE-2010-3080", "CVE-2010-3081", "CVE-2010-3301", "CVE-2010-3067", "CVE-2010-2960", "CVE-2010-2954", "CVE-2010-2955", "CVE-2010-2524", "CVE-2010-2478", "CVE-2010-2071");
  script_name("Fedora Update for kernel FEDORA-2010-18983");

  script_tag(name: "summary" , value: "Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

if(release == "FC13")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.34.7~66.fc13", rls:"FC13")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}