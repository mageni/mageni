###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sun_java_jre_mult_vuln_lin_apr10.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Sun Java JRE Multiple Vulnerabilities (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902168");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)");
  script_cve_id("CVE-2010-0886", "CVE-2010-0887", "CVE-2010-1423");
  script_bugtraq_id(39492);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Sun Java JRE Multiple Vulnerabilities (Linux)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JRE/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows execution of arbitrary code by tricking a user
  into visiting a malicious web page.");
  script_tag(name:"affected", value:"Sun Java version 6 Update 19 and prior on Linux.");
  script_tag(name:"insight", value:"The flaws are due to an input validation error in 'JRE' that does not
  properly validate arguments supplied via 'javaw.exe' before being passed to
  a 'CreateProcessA' call, which could allow remote attackers to automatically
  download and execute a malicious JAR file hosted on a network.");
  script_tag(name:"solution", value:"Upgrade to Sun Java version 6 Update 20.");
  script_tag(name:"summary", value:"This host is installed with Sun Java Deployment Toolkit and is prone to
  multiple vulnerabilities.");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/886582");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0853");
  script_xref(name:"URL", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2010-April/074036.html");
  script_xref(name:"URL", value:"http://www.reversemode.com/index.php?option=com_content&task=view&id=67&Itemid=1");
  script_xref(name:"URL", value:"http://java.sun.com/javase/6/");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

jreVer = get_app_version(cpe:"cpe:/a:sun:jre");
if(jreVer)
{
  if(version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.19")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
