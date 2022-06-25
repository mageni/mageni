###############################################################################
# OpenVAS Vulnerability Test
#
# HP-UX Update for Thunderbird HPSBUX02156
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
tag_impact = "Remote unauthorized access
  elevation of privileges
  Denial of Service (DoS)";
tag_affected = "Thunderbird on
  Thunderbird email application prior to v2.0.0.9 running on HP-UX B.11.11, 
  B.11.23, and B.11.31.";
tag_insight = "Potential security vulnerabilities have been identified with Thunderbird 
  running on HP-UX. These vulnerabilities could be exploited remotely 
  resulting in unauthorized access, elevation of privileges, or Denial of 
  Service (DoS).";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c00774579-4");
  script_oid("1.3.6.1.4.1.25623.1.0.307917");
  script_version("$Revision: 6584 $");
  script_cve_id("CVE-2006-0292", "CVE-2006-0293", "CVE-2006-0294", "CVE-2006-0295", 
                "CVE-2006-0296", "CVE-2006-0297", "CVE-2006-0298", "CVE-2006-0299", 
                "CVE-2006-0748", "CVE-2006-0884", "CVE-2006-1045", "CVE-2006-1529", 
                "CVE-2006-1530", "CVE-2006-1531", "CVE-2006-1723", "CVE-2006-1724", 
                "CVE-2006-1726", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1730", 
                "CVE-2006-2775", "CVE-2006-2776", "CVE-2006-2778", "CVE-2006-2779", 
                "CVE-2006-2780", "CVE-2006-2781", "CVE-2006-2783", "CVE-2006-2786", 
                "CVE-2006-2787", "CVE-2006-3113", "CVE-2006-3801", "CVE-2006-3802", 
                "CVE-2006-3803", "CVE-2006-3804", "CVE-2006-3805", "CVE-2006-3806", 
                "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810", 
                "CVE-2006-3811", "CVE-2007-1558", "CVE-2007-2867", "CVE-2007-2868", 
                "CVE-2007-3670", "CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3844", 
                "CVE-2007-3845", "CVE-2007-4841", "CVE-2007-5339", "CVE-2007-5340");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 16:13:23 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-05-05 12:14:23 +0200 (Tue, 05 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "HPSBUX", value: "02156");
  script_name( "HP-UX Update for Thunderbird HPSBUX02156");

  script_tag(name:"summary", value:"Check for the Version of Thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("HP-UX Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/hp_hp-ux", "ssh/login/release");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-hpux.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "HPUX11.31")
{

  if ((res = ishpuxpkgvuln(pkg:"Tbird.TBIRD-COM", revision:"2.0.0.9", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.23")
{

  if ((res = ishpuxpkgvuln(pkg:"Tbird.TBIRD-COM", revision:"2.0.0.9", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.11")
{

  if ((res = ishpuxpkgvuln(pkg:"Tbird.TBIRD-COM", revision:"2.0.0.9", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
