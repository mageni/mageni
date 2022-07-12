###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_java_se_hash_collision_dos_vuln_win.nasl 11855 2018-10-12 07:34:51Z cfischer $
#
# Oracle Java SE Hash Collision DoS Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802681");
  script_version("$Revision: 11855 $");
  script_cve_id("CVE-2012-2739");
  script_bugtraq_id(51236);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 09:34:51 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-12-04 15:27:32 +0530 (Tue, 04 Dec 2012)");
  script_name("Oracle Java SE Hash Collision DoS Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/903934");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/06/17/1");
  script_xref(name:"URL", value:"http://www.nruns.com/_downloads/advisory28122011.pdf");
  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2011-003.html");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=750533");
  script_xref(name:"URL", value:"http://armoredbarista.blogspot.de/2012/02/investigating-hashdos-issue.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to cause a denial of service
  condition via crafted input to an application that maintains a hash table.");
  script_tag(name:"affected", value:"Oracle Java SE 7 to 7 Update 5");
  script_tag(name:"insight", value:"The flaw is due to computes hash values without restricting the ability to
  trigger hash collisions predictably.");
  script_tag(name:"solution", value:"Upgrade to Oracle Java SE version 7 Update 6");
  script_tag(name:"summary", value:"This host is installed with Oracle Java SE and is prone to denial of
  service vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/java/javase/downloads/index.html");
  exit(0);
}

include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(jreVer)
{
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.5")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
