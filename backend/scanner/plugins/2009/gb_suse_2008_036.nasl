###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2008_036.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for libxcrypt SUSE-SA:2008:036
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
tag_impact = "use of weak password hash algorithm";
tag_affected = "libxcrypt on openSUSE 11.0";
tag_insight = "libxcrypt is used on openSUSE to calculate the hash value of
  passwords. It can be configured to use DES, MD5 or blowfish. Due to
  a bug in libxcrypt the DES algorithm was used if MD5 was configured
  in /etc/default/passwd. The default algorithm used on openSUSE is
  blowfish which worked as expected though.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.306207");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-3188");
  script_name( "SuSE Update for libxcrypt SUSE-SA:2008:036");

  script_tag(name:"summary", value:"Check for the Version of libxcrypt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "openSUSE11.0")
{

  if ((res = isrpmvuln(pkg:"libxcrypt", rpm:"libxcrypt~3.0~14.2", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxcrypt-devel", rpm:"libxcrypt-devel~3.0~14.2", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxcrypt-32bit", rpm:"libxcrypt-32bit~3.0~14.2", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}