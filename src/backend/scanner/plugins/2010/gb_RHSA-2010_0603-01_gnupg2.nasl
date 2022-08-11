###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for gnupg2 RHSA-2010:0603-01
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
tag_insight = "The GNU Privacy Guard (GnuPG or GPG) is a tool for encrypting data and
  creating digital signatures, compliant with the proposed OpenPGP Internet
  standard and the S/MIME standard.

  A use-after-free flaw was found in the way gpgsm, a Cryptographic Message
  Syntax (CMS) encryption and signing tool, handled X.509 certificates with
  a large number of Subject Alternate Names. A specially-crafted X.509
  certificate could, when imported, cause gpgsm to crash or, possibly,
  execute arbitrary code. (CVE-2010-2547)
  
  All gnupg2 users should upgrade to this updated package, which contains a
  backported patch to correct this issue.";

tag_affected = "gnupg2 on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-August/msg00008.html");
  script_oid("1.3.6.1.4.1.25623.1.0.312893");
  script_version("$Revision: 8469 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 08:58:21 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-06 10:34:50 +0200 (Fri, 06 Aug 2010)");
  script_xref(name: "RHSA", value: "2010:0603-01");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-2547");
  script_name("RedHat Update for gnupg2 RHSA-2010:0603-01");

  script_tag(name: "summary" , value: "Check for the Version of gnupg2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"gnupg2", rpm:"gnupg2~2.0.10~3.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnupg2-debuginfo", rpm:"gnupg2-debuginfo~2.0.10~3.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
