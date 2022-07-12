###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_java_se_mult_code_execution_vuln_win.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Oracle Java SE Multiple Remote Code Execution Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803156");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2012-3174", "CVE-2013-0422");
  script_bugtraq_id(57246, 57312);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-01-17 12:41:59 +0530 (Thu, 17 Jan 2013)");
  script_name("Oracle Java SE Multiple Remote Code Execution Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51820/");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027972");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/625617");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/java/javase/7u11-relnotes-1896856.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/alert-cve-2013-0422-1896849.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code
  via unspecified vectors.");
  script_tag(name:"affected", value:"Oracle Java version 7 before Update 11 on windows");
  script_tag(name:"solution", value:"Upgrade to Oracle Java 7 Update 11 or later.");
  script_tag(name:"summary", value:"This host is installed with Oracle Java SE and is prone to multiple
  code execution vulnerabilities.");
  script_tag(name:"insight", value:"- An error in Java Management Extensions (JMX) MBean components which allows
    remote attackers to execute arbitrary code via unspecified vectors.

  - An unspecified error exists within the Libraries subcomponent.

  NOTE: The vendor reports that only version 7.x is affected. However,
        some security researchers indicate that some 6.x versions may
        be affected");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(jreVer)
{
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.10")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
