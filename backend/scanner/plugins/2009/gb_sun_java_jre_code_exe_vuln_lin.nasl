###############################################################################
# OpenVAS Vulnerability Test
#
# Sun Java JRE Remote Code Execution Vulnerability (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800978");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-11-13 15:48:12 +0100 (Fri, 13 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3866", "CVE-2009-3886");
  script_bugtraq_id(36881);
  script_name("Sun Java JRE Remote Code Execution Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37231");
  script_xref(name:"URL", value:"http://java.sun.com/javase/6/webnotes/6u17.html");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-269870-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JRE/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code in
  the context of the affected application.");
  script_tag(name:"affected", value:"Sun Java JRE 6 prior to 6 Update 17 on Linux.");
  script_tag(name:"insight", value:"- An error occurs while using security model permissions when removing
  installer extensions and may allow an untrusted applications to run as a trusted application.

  - An error occurs while handling interaction between a signed JAR file
  and a JNLP application or applet.");
  script_tag(name:"solution", value:"Upgrade to JRE version 6 Update 17.");
  script_tag(name:"summary", value:"This host is installed with Sun Java JRE and is prone to Remote
  Code Execution Vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

jreVer = get_kb_item("Sun/Java/JRE/Linux/Ver");
if(!jreVer)
  exit(0);

if(version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.16")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
