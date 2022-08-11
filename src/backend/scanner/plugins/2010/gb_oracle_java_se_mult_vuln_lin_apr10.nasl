###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_java_se_mult_vuln_lin_apr10.nasl 14331 2019-03-19 14:03:05Z jschulte $
#
# Oracle Java SE Multiple Vulnerabilities (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800500");
  script_version("$Revision: 14331 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:03:05 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-07 16:20:50 +0200 (Wed, 07 Apr 2010)");
  script_cve_id("CVE-2009-3555", "CVE-2010-0082", "CVE-2010-0084", "CVE-2010-0085",
                "CVE-2010-0087", "CVE-2010-0088", "CVE-2010-0089", "CVE-2010-0090",
                "CVE-2010-0091", "CVE-2010-0092", "CVE-2010-0093", "CVE-2010-0094",
                "CVE-2010-0095", "CVE-2010-0837", "CVE-2010-0838", "CVE-2010-0839",
                "CVE-2010-0840", "CVE-2010-0841", "CVE-2010-0842", "CVE-2010-0843",
                "CVE-2010-0844", "CVE-2010-0845", "CVE-2010-0846", "CVE-2010-0847",
                "CVE-2010-0848", "CVE-2010-0849");
  script_bugtraq_id(36935, 39085, 39093, 39094, 39068, 39081, 39095, 39091, 39096,
                    39090, 39088, 39075, 39086, 39072, 39069, 39070, 39065, 39067,
                    39077, 39083, 39084, 39089, 39062, 39071, 39078, 39073);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Oracle Java SE Multiple Vulnerabilities (Linux)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0747");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Mar/1023774.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technology/deploy/security/critical-patch-updates/javacpumar2010.html");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JRE/Linux/Ver");
  script_tag(name:"impact", value:"Successful attacks will allow attackers to affect confidentiality, integrity,
  and availability via unknown vectors.");
  script_tag(name:"affected", value:"Sun Java SE version 6 Update 18, 5.0 Update 23 on Linux.");
  script_tag(name:"insight", value:"Multiple flaws are due to memory corruptions, buffer overflows, input
  validation and implementation errors in following components,

  - HotSpot Server,

  - Java Runtime Environment,

  - Java Web Start,

  - Java Plug-in,

  - Java 2D,

  - Sound and

  - imageIO components");
  script_tag(name:"solution", value:"Upgrade to SE 6 Update 19, JDK and JRE 5.0 Update 24.");
  script_tag(name:"summary", value:"This host is installed with Sun Java SE and is prone to multiple
  vulnerabilities.");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

jreVer = get_app_version(cpe:"cpe:/a:sun:jre");

if(jreVer)
{
  if(version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.18") ||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.23")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
